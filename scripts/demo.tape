# Tweek Security Demo — 4-Act Narrative
# Shows: unprotected AI assistant → injection → install Tweek → protected
# All pattern matching is REAL (no mock data)

Output assets/tweek-demo.gif

# Terminal settings
Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 650
Set Padding 20
Set Theme "Dracula"
Set WindowBar Colorful
Set WindowBarSize 40
Set TypingSpeed 0
Set CursorBlink false

# Run the demo (all timing is handled by the Python script)
Sleep 500ms
Type "python3 /Users/tmancino/AI/tweek-public/scripts/demo_terminal.py"
Enter

# Wait for the full demo to complete (~31s of sleeps + print time)
Sleep 36s
