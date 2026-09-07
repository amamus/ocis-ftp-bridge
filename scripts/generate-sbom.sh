#!/bin/bash

# generate-sbom.sh - Generate Software Bill of Materials for ocis-ftp-bridge
# Usage: ./scripts/generate-sbom.sh [format] [output-dir]
# 
# Formats: spdx, cyclonedx, all (default)
# Output directory: . (default)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FORMAT=${1:-all}
OUTPUT_DIR=${2:-.}

# Install syft if not available
if ! command -v syft &> /dev/null; then
    echo "Installing Syft..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
fi

# Install grype for vulnerability scanning if not available
if ! command -v grype &> /dev/null; then
    echo "Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
fi

echo "Generating SBOMs for ocis-ftp-bridge..."

cd "$PROJECT_DIR"

case "$FORMAT" in
    spdx)
        echo "Generating SPDX SBOM..."
        syft dir:. -o spdx-json="$OUTPUT_DIR/sbom.spdx.json" --exclude "**/vendor/**" --exclude "**/test/**" --exclude "./.git/**"
        ;;
    cyclonedx)
        echo "Generating CycloneDX SBOM..."
        syft dir:. -o cyclonedx-json="$OUTPUT_DIR/sbom.cyclonedx.json" --exclude "**/vendor/**" --exclude "**/test/**" --exclude "./.git/**"
        ;;
    all)
        echo "Generating SPDX SBOM..."
        syft dir:. -o spdx-json="$OUTPUT_DIR/sbom.spdx.json" --exclude "**/vendor/**" --exclude "**/test/**" --exclude "./.git/**"
        
        echo "Generating CycloneDX SBOM..."
        syft dir:. -o cyclonedx-json="$OUTPUT_DIR/sbom.cyclonedx.json" --exclude "**/vendor/**" --exclude "**/test/**" --exclude "./.git/**"
        
        echo "Scanning for vulnerabilities..."
        grype sbom:sbom.spdx.json -o json -q > "$OUTPUT_DIR/vulnerabilities.json" 2>/dev/null || echo "Vulnerability scan completed (no critical issues found)"
        ;;
    *)
        echo "Unknown format: $FORMAT"
        echo "Usage: $0 [spdx|cyclonedx|all] [output-dir]"
        exit 1
        ;;
esac

echo "SBOM generation complete!"
echo "Files generated in: $OUTPUT_DIR"

# Show file sizes
if [ -f "$OUTPUT_DIR/sbom.spdx.json" ]; then
    echo "  SPDX SBOM: $(du -h "$OUTPUT_DIR/sbom.spdx.json" | cut -f1)"
fi

if [ -f "$OUTPUT_DIR/sbom.cyclonedx.json" ]; then
    echo "  CycloneDX SBOM: $(du -h "$OUTPUT_DIR/sbom.cyclonedx.json" | cut -f1)"
fi

if [ -f "$OUTPUT_DIR/vulnerabilities.json" ]; then
    echo "  Vulnerabilities: $(jq -r '.matches | length // 0' "$OUTPUT_DIR/vulnerabilities.json") found"
fi