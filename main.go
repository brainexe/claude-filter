package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	// Create proxy server
	proxy, err := NewProxyServer()
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Start proxy in goroutine
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	wg.Go(func() {
		defer wg.Done()
		fmt.Printf("Starting proxy server on port %d\n", proxy.GetPort())
		if err := proxy.Start(); err != nil {
			log.Printf("Proxy server error: %v", err)
		}
	})

	// Give proxy a moment to start
	// todo needed?
	time.Sleep(10 * time.Millisecond)

	// Set up environment for Claude CLI to use the proxy
	env := os.Environ()
	env = append(env, fmt.Sprintf("HTTPS_PROXY=http://127.0.0.1:%d", proxy.GetPort()))
	env = append(env, fmt.Sprintf("HTTP_PROXY=http://127.0.0.1:%d", proxy.GetPort()))

	// Get claude CLI arguments (excluding the program name)
	claudeArgs := os.Args[1:]

	fmt.Printf("Claude Logger - Starting Claude CLI with proxy on port %d\n", proxy.GetPort())
	fmt.Println("Logs will be written to: request.log")

	// Create Claude CLI command
	cmd := exec.CommandContext(ctx, "claude", claudeArgs...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start Claude CLI in goroutine
	claudeFinished := make(chan error, 1)
	wg.Go(func() {
		defer wg.Done()
		claudeFinished <- cmd.Run()
	})

	// Wait for either Claude to finish or signal
	select {
	case err := <-claudeFinished:
		if err != nil {
			fmt.Printf("Claude CLI exited with error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Claude CLI finished successfully")
	case sig := <-sigChan:
		fmt.Printf("Received signal %v, shutting down...\n", sig)
		cancel() // This will cancel the context and stop Claude CLI
	}

	// Cancel context to stop proxy
	cancel()

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// todo forward signal to claude
	//	select {
	//	case <-done:
	//		fmt.Println("All processes stopped")
	//	case <-time.After(5 * time.Second):
	//		fmt.Println("Timeout waiting for processes to stop")
	//	}

	fmt.Println("Logs written to request.log")
}
