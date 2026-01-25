# Video 04: B.R.E.A.C.H. (Pentesting Workspace)

**Duration:** 12-15 min | **Focus:** Integrated terminal workspace with tracking

## Samples Needed

Place in `samples/`:

- [ ] Pre-populated engagement data (or create live)
- [ ] Sample credential dump for PRISM auto-parse demo
- [ ] Sample loot files (flags, SSH keys, configs)

## Scripts

Place in `scripts/`:

- [ ] `talking_points.md` - Section-by-section narration
- [ ] `workflow_demo.md` - End-to-end scenario steps
- [ ] `feature_tour.md` - UI features to highlight

## Pre-Recording Setup

- [ ] Neo4j running
- [ ] Sample engagement with 2-3 targets
- [ ] Some credentials pre-populated in vault
- [ ] Sample loot files ready
- [ ] Target VM accessible for nmap demo

## Key Demo Flow

```bash
# Launch
cd /home/kali/Desktop/KaliBackup/OSCP/crack/breach
./start.sh

# In GUI:
# 1. Show 3-panel layout
# 2. Point out engagement selector
# 3. Create new terminal tab
# 4. Create different session types (shell, scan)
# 5. Add target via sidebar form
# 6. Expand target - show services
# 7. Use nmap quick menu
# 8. Show credential vault
# 9. Demo "Use Credential" menu
# 10. Show loot panel
# 11. Switch engagements
```

## Key Shots

1. 3-panel workspace layout (establishing)
2. Terminal tabs with status indicators
3. Target sidebar with status dots
4. Nmap quick menu expansion
5. Credential vault domain grouping
6. "Use Credential" submenu (zoom)
7. Loot pattern detection badges
8. Engagement switcher dropdown

## Features to Demo

- [ ] Multi-tab terminals with types
- [ ] Session status indicators
- [ ] Target add form
- [ ] Service accordion expansion
- [ ] Nmap quick menu (6+ templates)
- [ ] Credential copy + use actions
- [ ] Loot preview modal
- [ ] Engagement switching

## Thumbnail Concept

Dark workspace with multiple terminal tabs, glowing target sidebar
Text: "One Window"
