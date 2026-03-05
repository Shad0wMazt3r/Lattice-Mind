import json, sqlite3
from collections import Counter
conn = sqlite3.connect('/data/runs.db')
conn.row_factory = sqlite3.Row
row = conn.execute(
    "SELECT steps FROM runs WHERE run_id LIKE '9a82fad0%'"
).fetchone()
steps = json.loads(row['steps'] or '[]')
print('total steps:', len(steps))
ev_counts = Counter(s.get('event', '') for s in steps)
for ev, cnt in ev_counts.most_common():
    print(f'  {ev}: {cnt}')

print()
print('--- env/printenv payloads ---')
for s in steps:
    d = s.get('data') or {}
    pp = str(d.get('payload_preview', ''))
    if 'env' in pp.lower() or 'printenv' in pp.lower():
        bp = str(d.get('body_preview', ''))
        print(f"[{s.get('step','?')}] {pp[:200]}")
        print(f"    body: {bp[:200]}")
