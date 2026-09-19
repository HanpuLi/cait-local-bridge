# Installation

## Packaged stdio server

Requirements: macOS, Python 3.12+ and pipx.

    brew install pipx  # skip if pipx is already installed
    pipx install "https://github.com/HanpuLi/scoperail/releases/download/v0.2.1/scoperail-0.2.1-py3-none-any.whl"
    scoperail --version
    scoperail init "$PWD"
    scoperail stdio

The tagged GitHub wheel is the current install source until the first PyPI Trusted Publishing upload is completed. After PyPI publication, `pipx install scoperail` installs the same application.

For an MCP client that launches the package itself, configure SCOPERAIL_WORKSPACE_ROOT and invoke scoperail-stdio. MCP Registry metadata uses the same stdio entry point once published.

Playwright browser automation also needs a Chromium browser installation appropriate to the environment.

## Source / full OAuth service

    git clone https://github.com/HanpuLi/scoperail.git
    cd scoperail
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
    ./scripts/install.sh

The source installer creates local state and launchd integration. A fresh checkout is intended to stay loopback-only until the operator configures a public URL and reverse-proxy or Tailscale exposure.

Remote exposure requires HTTPS, a correct public_url, and a review of SECURITY.md. Do not expose the loopback admin service.

## macOS permissions

Screenshot/native control requires Screen Recording and Accessibility permission for the actual Python or launcher process that runs the bridge. Grant these through System Settings only when needed.

## Upgrade

Back up ~/.scoperail before major upgrades. Package upgrades do not intentionally overwrite operator config, workspace registrations, grants or credentials.
