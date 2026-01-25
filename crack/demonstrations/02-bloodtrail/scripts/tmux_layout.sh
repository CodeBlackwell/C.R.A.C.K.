#!/bin/bash
# BloodTrail Demo - 3-Pane tmux Layout
# Usage: ./tmux_layout.sh [FOREST_IP]

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SESSION="bloodtrail-demo"
FOREST_IP="${1:-10.10.10.161}"
CRACK_DIR="$HOME/Desktop/OSCP/crack"

# Banner
echo -e "${RED}"
cat << 'EOF'
  ____  _                 _ _____          _ _
 | __ )| | ___   ___   __| |_   _| __ __ _(_) |
 |  _ \| |/ _ \ / _ \ / _` | | || '__/ _` | | |
 | |_) | | (_) | (_) | (_| | | || | | (_| | | |
 |____/|_|\___/ \___/ \__,_| |_||_|  \__,_|_|_|

EOF
echo -e "${NC}"
echo -e "${CYAN}3-Pane Demo Layout for Forest (HTB)${NC}"
echo -e "${YELLOW}Target: $FOREST_IP${NC}"
echo ""

# Check prerequisites
echo -e "${BLUE}[*] Checking prerequisites...${NC}"

# Check tmux
if ! command -v tmux &> /dev/null; then
    echo -e "${RED}[!] tmux not found. Install with: sudo apt install tmux${NC}"
    exit 1
fi
echo -e "${GREEN}[+] tmux found${NC}"

# Check Neo4j
if nc -z localhost 7687 2>/dev/null; then
    echo -e "${GREEN}[+] Neo4j running on port 7687${NC}"
else
    echo -e "${YELLOW}[!] Neo4j not detected. Start with: sudo neo4j start${NC}"
fi

# Check CRACK directory
if [ -d "$CRACK_DIR" ]; then
    echo -e "${GREEN}[+] CRACK directory found${NC}"
else
    echo -e "${RED}[!] CRACK directory not found at $CRACK_DIR${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}[*] Creating tmux session: $SESSION${NC}"

# Kill existing session if exists
tmux kill-session -t $SESSION 2>/dev/null

# Create new session with first pane (MANUAL)
tmux new-session -d -s $SESSION -n "demo" -x 200 -y 50

# Set up pane border styling
tmux set -t $SESSION pane-border-style "fg=colour240"
tmux set -t $SESSION pane-active-border-style "fg=colour208"
tmux set -t $SESSION pane-border-format " #{pane_title} "
tmux set -t $SESSION pane-border-status top

# Split horizontally for BLOODTRAIL pane (creates pane 1)
tmux split-window -h -t $SESSION:0.0 -p 50

# Now we have: [MANUAL 50%] | [RIGHT 50%]
# Split the left pane to create notes section at bottom
# Actually, let's do 2 vertical panes side by side

# Current layout: [0] | [1]
# We want: [MANUAL] | [BLOODTRAIL] with notes as overlay or separate

# For simplicity: 2 equal panes, BloodHound in separate window
tmux select-pane -t $SESSION:0.0 -T "MANUAL"
tmux select-pane -t $SESSION:0.1 -T "BLOODTRAIL"

# Set working directories and initial display
tmux send-keys -t $SESSION:0.0 "cd $CRACK_DIR" Enter
tmux send-keys -t $SESSION:0.0 "clear" Enter
tmux send-keys -t $SESSION:0.0 "echo -e '\\033[1;33m'" Enter
tmux send-keys -t $SESSION:0.0 "figlet -f small 'MANUAL' 2>/dev/null || echo '=== MANUAL COMMANDS ==='" Enter
tmux send-keys -t $SESSION:0.0 "echo -e '\\033[0m'" Enter
tmux send-keys -t $SESSION:0.0 "echo 'Raw Impacket / rpcclient / ldapsearch commands'" Enter
tmux send-keys -t $SESSION:0.0 "echo 'Target: $FOREST_IP'" Enter
tmux send-keys -t $SESSION:0.0 "echo ''" Enter

tmux send-keys -t $SESSION:0.1 "cd $CRACK_DIR" Enter
tmux send-keys -t $SESSION:0.1 "clear" Enter
tmux send-keys -t $SESSION:0.1 "echo -e '\\033[1;32m'" Enter
tmux send-keys -t $SESSION:0.1 "figlet -f small 'BLOODTRAIL' 2>/dev/null || echo '=== BLOODTRAIL OUTPUT ==='" Enter
tmux send-keys -t $SESSION:0.1 "echo -e '\\033[0m'" Enter
tmux send-keys -t $SESSION:0.1 "echo 'Guided attack path discovery'" Enter
tmux send-keys -t $SESSION:0.1 "echo 'Target: $FOREST_IP'" Enter
tmux send-keys -t $SESSION:0.1 "echo ''" Enter

# Select the BLOODTRAIL pane as default
tmux select-pane -t $SESSION:0.1

echo ""
echo -e "${GREEN}[+] tmux session created!${NC}"
echo ""
echo -e "${CYAN}Layout:${NC}"
echo "  +------------------+------------------+"
echo "  |     MANUAL       |   BLOODTRAIL     |"
echo "  | (Pane 0)         | (Pane 1)         |"
echo "  |                  |                  |"
echo "  | Raw commands     | Guided output    |"
echo "  +------------------+------------------+"
echo ""
echo -e "${YELLOW}Instructions:${NC}"
echo "  1. Open BloodHound GUI in separate window"
echo "  2. Connect to Neo4j (bolt://localhost:7687)"
echo "  3. Run demo commands in each pane"
echo ""
echo -e "${BLUE}Attaching to session...${NC}"
echo -e "${CYAN}(Ctrl+B then D to detach)${NC}"
echo ""

sleep 1

# Attach to session
tmux attach -t $SESSION
