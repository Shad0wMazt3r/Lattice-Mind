import json, sqlite3

conn = sqlite3.connect('/data/runs.db')
conn.row_factory = sqlite3.Row

for rid in ('fa4df531', '626a4b96'):
    row = conn.execute(
        "SELECT steps FROM runs WHERE run_id LIKE ?", (rid + '%',)
    ).fetchone()
    steps = json.loads(row['steps'] or '[]')
    print(f"=== {rid} ===")
    for s in steps:
        if s.get('event') == 'exploit_result':
            d = s.get('data') or {}
            body = d.get('body_preview', '')
            print(f"Step {s.get('step')}: {s.get('node_id')}")
            print(f"Payload: {d.get('payload_preview','')}")
            print(f"Full body_preview ({len(body)} chars):")
            print(repr(body))
            print()
            break
    print()
