#!/bin/sh
# 1611: a cloud session of any repo gets the owner's one rules file and guard hooks from the studio (the one base), put
# where the owner's computer keeps them (~/.claude), and "py" for the studio tool as on Windows. Needs STUDIO_OWNER_KEY in
# the cloud environment. Sessions on the owner's computer skip this - their ~/.claude is the source the studio gets.
[ "$CLAUDE_CODE_REMOTE" = true ] || exit 0
mkdir -p "$HOME/.claude/hooks"
curl -fsS "https://pvvslmxgzgjuszsoatvp.supabase.co/functions/v1/studio?api=rules&k=$STUDIO_OWNER_KEY" | python3 -c '
import json, os, sys
home = os.path.join(os.path.expanduser("~"), ".claude")
for name, text in json.loads(sys.stdin.buffer.read().decode("utf-8")).items():
    with open(os.path.join(home, name), "w", encoding="utf-8") as f:
        f.write(text)
' || echo "rules not loaded - is STUDIO_OWNER_KEY set in the cloud environment?" >&2
command -v py >/dev/null || ln -sf "$(command -v python3)" /usr/local/bin/py 2>/dev/null || true
exit 0
