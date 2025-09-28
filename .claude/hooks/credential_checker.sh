#!/bin/bash

# Credential checker hook for Claude Code
# Checks tool outputs for secrets using gitleaks

set -euo pipefail

HOOK_DIR="$(dirname "$0")"
GITLEAKS_PATH="$HOOK_DIR/gitleaks"
LOG_FILE="$HOOK_DIR/gitleaks.log"
LOGGING=1

# Logging function
log() {
    [[ $LOGGING -eq 1 ]] || return
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

log "=== HOOK STARTED ==="

# Map system architecture to gitleaks naming convention
get_gitleaks_arch() {
    local os=$(uname -s)
    local arch=$(uname -m)

    case "$os" in
        "Linux")
            case "$arch" in
                "x86_64") echo "linux_x64" ;;
                "aarch64"|"arm64") echo "linux_arm64" ;;
                "armv6l") echo "linux_armv6" ;;
                "armv7l") echo "linux_armv7" ;;
                "i686"|"i386") echo "linux_x32" ;;
                *) echo "unsupported" ;;
            esac
            ;;
        "Darwin")
            case "$arch" in
                "x86_64") echo "darwin_x64" ;;
                "arm64") echo "darwin_arm64" ;;
                *) echo "unsupported" ;;
            esac
            ;;
        *)
            echo "unsupported"
            ;;
    esac
}

# Install gitleaks if not present
install_gitleaks() {
    local gitleaks_arch=$(get_gitleaks_arch)
    log "Installing gitleaks for architecture: $gitleaks_arch"

    if [[ "$gitleaks_arch" == "unsupported" ]]; then
        log "ERROR: Unsupported architecture: $(uname -s) $(uname -m)"
        echo "❌ Unsupported architecture: $(uname -s) $(uname -m)" >&2
        echo "Please install gitleaks manually from: https://github.com/gitleaks/gitleaks/releases" >&2
        exit 1
    fi

    local download_url="https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_${gitleaks_arch}.tar.gz"
    log "Download URL: $download_url"

    echo "🔧 Installing gitleaks for ${gitleaks_arch}..." >&2
    echo "📥 Downloading from: $download_url" >&2

    if ! curl -sL "$download_url" | tar -xz -C "$HOOK_DIR" gitleaks 2>>"$LOG_FILE"; then
        log "ERROR: Failed to install gitleaks"
        echo "❌ Failed to install gitleaks for $gitleaks_arch" >&2
        echo "URL: $download_url" >&2
        exit 1
    fi

    chmod +x "$GITLEAKS_PATH"
    log "SUCCESS: Gitleaks installed at $GITLEAKS_PATH"
    echo "✅ Gitleaks installed successfully at $GITLEAKS_PATH" >&2
}

# Check if gitleaks is available
if [[ ! -x "$GITLEAKS_PATH" ]]; then
    log "Gitleaks not found, installing..."
    install_gitleaks
else
    log "Gitleaks found at: $GITLEAKS_PATH"
fi

# Test gitleaks
GITLEAKS_VERSION=$("$GITLEAKS_PATH" version 2>>"$LOG_FILE" || echo "unknown")
log "Gitleaks version: $GITLEAKS_VERSION"

# Read the hook input
INPUT=$(cat)
log "Raw hook input received (length: ${#INPUT})"

# Extract tool name
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"' 2>>"$LOG_FILE")
log "Tool name: $TOOL_NAME"

# Log the entire input for debugging
echo "=== FULL HOOK INPUT ===" >> "$LOG_FILE"
echo "$INPUT" >> "$LOG_FILE"
echo "=== END HOOK INPUT ===" >> "$LOG_FILE"

# Extract output based on tool type
COMMAND_OUTPUT=""
case "$TOOL_NAME" in
    "Bash")
        COMMAND_OUTPUT=$(echo "$INPUT" | jq -r '.tool_response.stdout // .tool_response.stderr // ""' 2>>"$LOG_FILE" || echo "")
        ;;
    "Read")
        COMMAND_OUTPUT=$(echo "$INPUT" | jq -r '.tool_response.file.content // ""' 2>>"$LOG_FILE" || echo "")
        ;;
    *)
        # Try to extract any text content
        COMMAND_OUTPUT=$(echo "$INPUT" | jq -r '.tool_output | if type == "object" then ((.stdout // "") + (.stderr // "") + (.content // "") + (.text // "")) else . end' 2>>"$LOG_FILE" || echo "")
        ;;
esac

log "Extracted output for $TOOL_NAME (length: ${#COMMAND_OUTPUT}): ${COMMAND_OUTPUT:0:100}..."

# Log the command output being checked
echo "=== CONTENT TO CHECK ===" >> "$LOG_FILE"
echo "$COMMAND_OUTPUT" >> "$LOG_FILE"
echo "=== END CONTENT ===" >> "$LOG_FILE"

# Skip if no output to check
if [[ -z "$COMMAND_OUTPUT" ]]; then
    log "No content to check, exiting"
    exit 0
fi

# Run gitleaks on the output
TEMP_RESULT=$(mktemp)
TEMP_INPUT=$(mktemp)
trap "rm -f $TEMP_RESULT $TEMP_INPUT" EXIT

# Save input to temporary file for gitleaks
echo "$COMMAND_OUTPUT" > "$TEMP_INPUT"

log "Running gitleaks on $TOOL_NAME output..."
# Run gitleaks and capture both stdout and stderr
GITLEAKS_EXIT_CODE=0
echo "$COMMAND_OUTPUT" | "$GITLEAKS_PATH" stdin --redact=90 --no-banner --no-color -v > "$TEMP_RESULT" 2>>"$LOG_FILE" || GITLEAKS_EXIT_CODE=$?

log "Gitleaks exit code: $GITLEAKS_EXIT_CODE"

# Log gitleaks output
echo "=== GITLEAKS OUTPUT ===" >> "$LOG_FILE"
cat "$TEMP_RESULT" >> "$LOG_FILE"
echo "=== END GITLEAKS OUTPUT ===" >> "$LOG_FILE"

if [[ $GITLEAKS_EXIT_CODE -eq 0 ]]; then
    # No secrets found
    log "No secrets detected in $TOOL_NAME output, allowing"
    exit 0
fi

echo "🚨 **CREDENTIAL ALERT** ($TOOL_NAME tool)" >&2
echo "" >&2
echo "**Gitleaks detected otential credential(s) in the $TOOL_NAME output:**" >&2
echo "" >&2

# Show first few lines of findings
head -n 10 "$TEMP_RESULT" | sed 's/^/  /' >&2

exit 2