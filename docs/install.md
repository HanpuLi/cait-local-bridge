# Installation

## Packaged stdio server

Requirements: macOS and Python 3.12+.

    python3 -m pip install cait-local-bridge
    cait-local-bridge --version
    cait-local-bridge init "$PWD"
    cait-local-bridge stdio

For an MCP client that launches the package itself, configure CLB_WORKSPACE_ROOT and invoke cait-local-bridge-stdio. MCP Registry metadata uses the same stdio entry point once published.

Playwright browser automation also needs a Chromium browser installation appropriate to the environment.

## Source / full OAuth service

    git clone https://github.com/HanpuLi/cait-local-bridge.git
    cd cait-local-bridge
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
    ./scripts/install.sh

The source installer creates local state and launchd integration. A fresh checkout is intended to stay loopback-only until the operator configures a public URL and reverse-proxy or Tailscale exposure.

Remote exposure requires HTTPS, a correct public_url, and a review of SECURITY.md. Do not expose the loopback admin service.

## macOS permissions

Screenshot/native control requires Screen Recording and Accessibility permission for the actual Python or launcher process that runs the bridge. Grant these through System Settings only when needed.

## Upgrade

Back up ~/.cait-local-bridge before major upgrades. Package upgrades do not intentionally overwrite operator config, workspace registrations, grants or credentials.
