package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type ProxyServer struct {
	port     int
	logFile  *os.File
	detector *detect.Detector
}

type LogEntry struct {
	Timestamp    string                `json:"timestamp"`
	URL          string                `json:"url"`
	Method       string                `json:"method"`
	UserMessages []string              `json:"user_messages,omitempty"`
	ToolCalls    []ToolCall            `json:"tool_calls,omitempty"`
	ToolResults  []ToolResult          `json:"tool_results,omitempty"`
	Credentials  []CredentialDetection `json:"credentials,omitempty"`
	Blocked      bool                  `json:"blocked,omitempty"`
	ResponseBody interface{}           `json:"response_body,omitempty"`
}

type ToolCall struct {
	Name  string      `json:"name"`
	Input interface{} `json:"input"`
}

type ToolResult struct {
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
}

type CredentialDetection struct {
	RuleID      string `json:"rule_id"`
	Match       string `json:"match"`
	Secret      string `json:"secret"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
}

type ClaudeRequest struct {
	Messages []Message `json:"messages"`
}

type ClaudeResponse struct {
	Content []Content `json:"content"`
}

type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type Content struct {
	Type      string      `json:"type"`
	Text      string      `json:"text,omitempty"`
	Name      string      `json:"name,omitempty"`
	Input     interface{} `json:"input,omitempty"`
	ToolUseID string      `json:"tool_use_id,omitempty"`
}

func NewProxyServer() (*ProxyServer, error) {
	// Find a random available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Open log file
	logFile, err := os.OpenFile("request.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	// Initialize gitleaks detector with default config
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		logFile.Close()
		return nil, fmt.Errorf("failed to initialize gitleaks detector: %v", err)
	}

	return &ProxyServer{
		port:     port,
		logFile:  logFile,
		detector: detector,
	}, nil
}

func (p *ProxyServer) Start() error {
	defer p.logFile.Close()

	fmt.Printf("Starting proxy server on port %d\n", p.port)

	server := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", p.port),
		Handler: http.HandlerFunc(p.handleRequest),
	}

	return server.ListenAndServe()
}

func (p *ProxyServer) GetPort() int {
	return p.port
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Create log entry
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		URL:       r.URL.String(),
		Method:    r.Method,
	}

	// Read request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Check for credentials in request body
	if len(bodyBytes) > 0 {
		credentials := p.detectCredentials(string(bodyBytes))
		if len(credentials) > 0 {
			entry.Credentials = credentials
			entry.Blocked = true
			p.logEntry(entry)

			fmt.Printf("⚠️  CREDENTIAL DETECTED: Found %d potential credential(s)\n", len(credentials))
			for i, cred := range credentials {
				fmt.Printf("    %d. %s: %s\n", i+1, cred.RuleID, cred.Match)
			}
			fmt.Printf("🚫 REQUEST BLOCKED - Request has been aborted to prevent credential transmission\n")

			http.Error(w, "Request blocked due to credential detection", http.StatusForbidden)
			return
		}

		// Parse request body for user messages and tool calls if it's a Claude API request
		if strings.Contains(r.URL.Path, "/messages") {
			p.parseClaudeRequest(string(bodyBytes), &entry)
		}
	}

	// Forward the request
	resp, err := p.forwardRequest(r, bodyBytes)
	if err != nil {
		log.Printf("Error forwarding request: %v", err)
		http.Error(w, "Error forwarding request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		http.Error(w, "Error reading response body", http.StatusBadGateway)
		return
	}

	// Parse response for tool calls if it's a Claude API response
	if strings.Contains(r.URL.Path, "/messages") && len(responseBody) > 0 {
		p.parseClaudeResponse(string(responseBody), &entry)
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(responseBody)

	// Log the entry
	p.logEntry(entry)
}

func (p *ProxyServer) forwardRequest(r *http.Request, bodyBytes []byte) (*http.Response, error) {
	// Create the target URL
	targetURL := r.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "https"
	}
	if targetURL.Host == "" {
		targetURL.Host = "api.anthropic.com"
	}

	// Create new request
	req, err := http.NewRequest(r.Method, targetURL.String(), bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Create HTTP client with custom transport to handle SSL and DNS
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout: time.Millisecond * 200,
						}
						return d.DialContext(ctx, network, "8.8.8.8:53")
					},
				},
			}).DialContext,
		},
		Timeout: 60 * time.Second,
	}

	return client.Do(req)
}

func (p *ProxyServer) detectCredentials(content string) []CredentialDetection {
	var detections []CredentialDetection

	// Detect secrets directly from string
	findings := p.detector.DetectString(content)

	// Convert findings to our format
	for _, finding := range findings {
		detections = append(detections, CredentialDetection{
			RuleID:      finding.RuleID,
			Match:       finding.Match,
			Secret:      finding.Secret,
			StartLine:   finding.StartLine,
			EndLine:     finding.EndLine,
			StartColumn: finding.StartColumn,
			EndColumn:   finding.EndColumn,
		})
	}

	return detections
}

func (p *ProxyServer) parseClaudeRequest(body string, entry *LogEntry) {
	var req ClaudeRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return
	}

	for _, message := range req.Messages {
		if message.Role == "user" {
			// Handle different content types
			switch content := message.Content.(type) {
			case string:
				entry.UserMessages = append(entry.UserMessages, content)
			case []interface{}:
				for _, part := range content {
					if partMap, ok := part.(map[string]interface{}); ok {
						if partMap["type"] == "text" {
							if text, ok := partMap["text"].(string); ok {
								entry.UserMessages = append(entry.UserMessages, text)
							}
						} else if partMap["type"] == "tool_result" {
							if toolUseID, ok := partMap["tool_use_id"].(string); ok {
								if resultContent, ok := partMap["content"].(string); ok {
									entry.ToolResults = append(entry.ToolResults, ToolResult{
										ToolUseID: toolUseID,
										Content:   resultContent[:min(200, len(resultContent))],
									})
								}
							}
						}
					}
				}
			}
		} else if message.Role == "assistant" {
			// Handle tool calls in assistant messages
			if contentArray, ok := message.Content.([]interface{}); ok {
				for _, part := range contentArray {
					if partMap, ok := part.(map[string]interface{}); ok {
						if partMap["type"] == "tool_use" {
							if name, ok := partMap["name"].(string); ok {
								entry.ToolCalls = append(entry.ToolCalls, ToolCall{
									Name:  name,
									Input: partMap["input"],
								})
							}
						}
					}
				}
			}
		}
	}
}

func (p *ProxyServer) parseClaudeResponse(body string, entry *LogEntry) {
	var resp ClaudeResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return
	}

	for _, content := range resp.Content {
		if content.Type == "tool_use" {
			entry.ToolCalls = append(entry.ToolCalls, ToolCall{
				Name:  content.Name,
				Input: content.Input,
			})
		}
	}

	// Store the response body (truncated if too large)
	var responseMap map[string]interface{}
	if err := json.Unmarshal([]byte(body), &responseMap); err == nil {
		entry.ResponseBody = responseMap
	}
}

func (p *ProxyServer) logEntry(entry LogEntry) {
	// Write JSON entry to log file
	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Error marshaling log entry: %v", err)
		return
	}

	logLine := string(jsonData) + "\n"

	// Write to log file
	if _, err := p.logFile.WriteString(logLine); err != nil {
		log.Printf("Error writing to log file: %v", err)
	}

	p.logFile.Sync()

	// Also print human-readable output to console for debugging
	fmt.Printf("%s %s", entry.Timestamp, entry.URL)

	if len(entry.Credentials) > 0 {
		fmt.Printf("\n  ⚠️  CREDENTIAL DETECTED: Found %d potential credential(s)", len(entry.Credentials))
		for i, cred := range entry.Credentials {
			fmt.Printf("\n    %d. %s: %s", i+1, cred.RuleID, cred.Match)
		}
		if entry.Blocked {
			fmt.Printf("\n  🚫 REQUEST BLOCKED - High-confidence credential detected, request aborted")
		}
	}

	if len(entry.UserMessages) > 0 {
		fmt.Printf("\n")
		for i, msg := range entry.UserMessages {
			fmt.Printf("  User Message %d: %s\n", i+1, msg)
		}
	}

	if len(entry.ToolCalls) > 0 {
		fmt.Printf("  Tool Calls:\n")
		for i, toolCall := range entry.ToolCalls {
			inputJSON, _ := json.Marshal(toolCall.Input)
			fmt.Printf("    %d. %s(%s)\n", i+1, toolCall.Name, string(inputJSON))
		}
	}

	if len(entry.ToolResults) > 0 {
		fmt.Printf("  Tool Results:\n")
		for i, result := range entry.ToolResults {
			fmt.Printf("    %d. %s: %s\n", i+1, result.ToolUseID, result.Content)
		}
	}

	fmt.Printf("\n")
}
