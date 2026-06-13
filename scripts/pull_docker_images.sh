#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# AI-DTCTM | Pull vulnerable app images for Digital Twin targets
# ═══════════════════════════════════════════════════════════════════
# Run once after Docker Desktop is installed. Pulls the 3 target apps
# that the Digital Twin engine will clone and attack safely.
#
# Usage:
#   chmod +x scripts/pull_docker_images.sh
#   ./scripts/pull_docker_images.sh
#
# Total download: ~1.5 GB. Run on decent Wi-Fi.

set -e

echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │  AI-DTCTM · Pulling Digital Twin target images          │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""

# Verify Docker is running
if ! docker info > /dev/null 2>&1; then
  echo "  ✗ Docker is not running. Start Docker Desktop first."
  exit 1
fi

echo "  ✓ Docker daemon reachable"
echo ""

IMAGES=(
  "vulnerables/web-dvwa:latest         # Damn Vulnerable Web App (classic SQLi/XSS playground)"
  "webgoat/goat-and-wolf:latest        # WebGoat — OWASP training lessons"
  "bkimminich/juice-shop:latest        # OWASP Juice Shop — modern SPA with 100+ challenges"
)

for entry in "${IMAGES[@]}"; do
  image="${entry%% *}"
  echo "  ──── Pulling $image ────"
  docker pull "$image"
  echo ""
done

# Create the isolated twin network if it doesn't exist
NETWORK="${DOCKER_TWIN_NETWORK:-aidtctm_twin_net}"
if ! docker network inspect "$NETWORK" > /dev/null 2>&1; then
  echo "  ──── Creating isolated twin network: $NETWORK ────"
  docker network create --internal "$NETWORK" > /dev/null
  echo "  ✓ Network created (internal — no internet access for twins)"
fi

echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │  ✓ All images pulled and network ready                  │"
echo "  │                                                         │"
echo "  │  Verify:                                                │"
echo "  │    docker images | grep -E 'dvwa|webgoat|juice-shop'    │"
echo "  │                                                         │"
echo "  │  Quick smoke test (DVWA):                               │"
echo "  │    docker run --rm -d -p 8081:80 --name dvwa-test \\    │"
echo "  │      vulnerables/web-dvwa                               │"
echo "  │    # Visit http://localhost:8081                        │"
echo "  │    docker stop dvwa-test                                │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
