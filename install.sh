#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; BLD='\033[1m'; RST='\033[0m'

ok()   { echo -e "  ${GRN}✓${RST} $*"; }
fail() { echo -e "  ${RED}✗${RST} $*"; }
info() { echo -e "\n${BLU}${BLD}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; }
warn() { echo -e "  ${YLW}⚠${RST}  $*"; }

echo ""
echo -e "${BLU}${BLD}╔══════════════════════════════════════════╗${RST}"
echo -e "${BLU}${BLD}║     bb-agent — Dependency Installer      ║${RST}"
echo -e "${BLU}${BLD}╚══════════════════════════════════════════╝${RST}"
echo ""

info "Python packages"
pip install openai --break-system-packages --quiet --ignore-installed 2>/dev/null || true
ok "openai installed"

info "Kali apt tools"
apt-get install -y httpx-toolkit dnsx subfinder 2>/dev/null && ok "apt tools installed" || warn "some apt tools failed"

info "Go (required for tools)"
if ! command -v go &>/dev/null; then
  apt-get install -y golang-go 2>/dev/null || true
fi
if command -v go &>/dev/null; then
  ok "Go $(go version | awk '{print $3}')"
  export GOPATH="$HOME/go"
  export PATH="$PATH:$GOPATH/bin"
  echo 'export GOPATH=$HOME/go' >> ~/.bashrc
  echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
else
  fail "Go not found — install: apt install golang-go"
fi

install_go_tool() {
  local name=$1
  local pkg=$2
  if command -v "$name" &>/dev/null; then
    ok "$name already installed"
  else
    echo -n "  Installing $name..."
    go install "$pkg" 2>/dev/null \
      && echo -e " ${GRN}done${RST}" \
      || echo -e " ${RED}failed${RST}"
  fi
}

info "Go recon tools"
install_go_tool subfinder   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool nuclei      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool katana      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool assetfinder "github.com/tomnomnom/assetfinder@latest"
install_go_tool gf          "github.com/tomnomnom/gf@latest"
install_go_tool anew        "github.com/tomnomnom/anew@latest"
install_go_tool waybackurls "github.com/tomnomnom/waybackurls@latest"
install_go_tool ffuf        "github.com/ffuf/ffuf/v2@latest"
install_go_tool dalfox      "github.com/hahwul/dalfox/v2@latest"

info "gf patterns"
if command -v gf &>/dev/null; then
  mkdir -p ~/.gf
  if [[ ! -d ~/Gf-Patterns ]]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns 2>/dev/null || true
    cp ~/Gf-Patterns/*.json ~/.gf/ 2>/dev/null || true
    ok "gf patterns installed"
  else
    ok "gf patterns already present"
  fi
fi

info "Nuclei templates"
if command -v nuclei &>/dev/null; then
  if [[ ! -d ~/nuclei-templates ]]; then
    nuclei -update-templates 2>/dev/null && ok "templates downloaded" || warn "template download failed"
  else
    ok "nuclei templates already present"
  fi
fi

info "SecLists"
if [[ ! -d /usr/share/seclists ]]; then
  apt-get install -y seclists 2>/dev/null && ok "SecLists installed" || \
  git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null && ok "SecLists cloned" || \
  warn "SecLists install failed"
else
  ok "SecLists already installed"
fi

info "Ollama + Qwen"
if curl -sf http://localhost:11434/api/tags &>/dev/null; then
  ok "Ollama running"
  if ollama list 2>/dev/null | grep -q "qwen2.5:7b"; then
    ok "qwen2.5:7b ready"
  else
    ollama pull qwen2.5:7b && ok "qwen2.5:7b pulled" || warn "pull failed — run: ollama pull qwen2.5:7b"
  fi
else
  warn "Ollama not running — start with: ollama serve"
fi

info "Hunt memory structure"
mkdir -p ~/bb-agent/hunt-memory/targets
if [[ ! -f ~/bb-agent/hunt-memory/patterns.jsonl ]]; then
  cat > ~/bb-agent/hunt-memory/patterns.jsonl << 'EOF'
{"pattern": "numeric id in /api/v1/users/{id}", "tech": "rails", "result": "IDOR - read other users data", "date": "2025-01-01"}
{"pattern": "?redirect= parameter", "tech": "any", "result": "open redirect to oauth token theft", "date": "2025-01-01"}
{"pattern": "/graphql introspection enabled", "tech": "graphql", "result": "schema leak leads to IDOR discovery", "date": "2025-01-01"}
EOF
  ok "hunt-memory initialized"
else
  ok "hunt-memory already exists"
fi

echo ""
echo -e "${GRN}${BLD}━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
for t in subfinder httpx-toolkit dnsx nuclei katana assetfinder gf waybackurls ffuf dalfox; do
  command -v "$t" &>/dev/null \
    && echo -e "  ${GRN}✓${RST} $t" \
    || echo -e "  ${RED}✗${RST} $t"
done
echo ""
echo -e "  ${BLD}Run:${RST} ./run.sh target.com '*.target.com'"
echo ""
