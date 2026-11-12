# winbox — install / dev / test helpers
#
# Quick start:
#   make apt       # system dependencies (needs sudo)
#   make install   # install everything via pipx (force-reinstalls)
#
# Developer:
#   make apt install-dev
#   make test
#
# `make` or `make help` lists every target.

SHELL := bash -euo pipefail
.DEFAULT_GOAL := help

# --- package sets -----------------------------------------------------------

# Hard requirements: without these `winbox setup` / exec won't work.
# libwin-hivex-perl provides `hivexregedit`, needed to disable Defender in the
# offline registry hive on the client/24H2 profiles (win10, win11, server2025).
APT_REQUIRED := \
	qemu-system-x86 \
	qemu-utils \
	libvirt-daemon-system \
	virtinst \
	libguestfs-tools \
	virtiofsd \
	p7zip-full \
	genisoimage \
	sshpass \
	wget \
	libwin-hivex-perl

# Optional: enable specific features.
#   virt-manager -> `winbox vnc`
#   llvm         -> `llvm-undname`, C++ symbol demangling in `winbox kdbg`
#   tshark       -> packet capture during malware detonation (dumpcap)
#   inetsim      -> fake HTTP/DNS/etc. services for detonation
#   acl          -> setfacl, used when granting VirtIO-FS share access
APT_OPTIONAL := \
	virt-manager \
	llvm \
	tshark \
	inetsim \
	acl

APT ?= sudo apt-get
PIPX ?= pipx
# Extras baked into the pipx install. `[mcp]` ships the MCP server; drop it
# with `make install PKG_EXTRAS=`.
PKG_EXTRAS ?= [mcp]

# --- help -------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- system dependencies (apt) ----------------------------------------------

.PHONY: apt
apt: ## Install required + optional system packages (sudo)
	$(APT) update
	$(APT) install -y $(APT_REQUIRED) $(APT_OPTIONAL)

# --- install ----------------------------------------------------------------

.PHONY: install
install: ## Force-(re)install the winbox CLI via pipx with all dependencies
	command -v $(PIPX) >/dev/null 2>&1 || { \
		echo ">> pipx not found, installing via apt"; \
		$(APT) update && $(APT) install -y pipx; }
	$(PIPX) ensurepath
	$(PIPX) install --force '.$(PKG_EXTRAS)'
	@echo ">> installed. If 'winbox' isn't found, open a new shell (pipx ensurepath)."

.PHONY: install-dev
install-dev: ## Editable dev install into a local .venv with dev + mcp extras
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -e '.[dev,mcp]'
	@echo ">> dev env ready. Activate with: source .venv/bin/activate"

.PHONY: uninstall
uninstall: ## Remove the pipx-installed winbox CLI
	$(PIPX) uninstall winbox

# --- test -------------------------------------------------------------------

# Runs unit tests. Prefers the .venv from install-dev; otherwise falls back to
# running against ./src directly (no install needed). Integration tests are
# excluded by default (they drive a live VM) — use `make test-integration`.
.PHONY: test
test: ## Run unit tests (integration excluded)
	@if [ -x .venv/bin/pytest ]; then \
		.venv/bin/python -m pytest; \
	else \
		PYTHONPATH=src python3 -m pytest; \
	fi

.PHONY: test-integration
test-integration: ## Run integration tests — DRIVES THE LIVE VM
	@if [ -x .venv/bin/pytest ]; then \
		.venv/bin/python -m pytest -m integration; \
	else \
		PYTHONPATH=src python3 -m pytest -m integration; \
	fi

# --- housekeeping -----------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache
	find . -type d -name __pycache__ -not -path './.venv/*' -exec rm -rf {} + 2>/dev/null || true
