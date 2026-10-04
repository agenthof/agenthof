# every-door-demo.tape — the README "every door" gif.
#
# Regenerate:  vhs docs/assets/every-door-demo.tape
# Requires: go, and a python with examples/langchain-agent/requirements.txt
# installed, both on PATH (set PYTHON=<interpreter> to pick a specific one).
# It records scripts/demo-every-door.sh — one governed run that drives every
# door, the merged investigate tree, and the integrity check, all hermetically
# (stand-ins; no podman, no real model, no secrets).
Output docs/assets/every-door-demo.gif
Require bash
Set Shell bash
Set FontSize 15
Set Width 1180
Set Height 880
Set Padding 18
Set TypingSpeed 18ms
Type "./scripts/demo-every-door.sh"
Sleep 500ms
Enter
Sleep 31s
