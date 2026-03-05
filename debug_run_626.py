import json, sqlite3, re
from collections import Counter
conn = sqlite3.connect('/data/runs.db')
conn.row_factory = sqlite3.Row

# All runs chronologically
rows = conn.execute('SELECT run_id, status, flag, created_at FROM runs ORDER BY created_at').fetchall()
print('All runs (chronological):')
for r in rows:
    rid = r['run_id'][:8]
    status = r['status']
    flag = r['flag']
    created = r['created_at']
    print(f'  {rid}  status={status:12}  flag={flag}  created={created}')

print()

# Detail run 626a4b96
row = conn.execute(
    "SELECT run_id,status,flag,created_at,finished_at,steps,challenge FROM runs WHERE run_id LIKE '626a4b96%'"
).fetchone()
if not row:
    print('626a4b96 not found')
    exit(1)

steps = json.loads(row['steps'] or '[]')
ch = json.loads(row['challenge'] or '{}')
flag_re = re.compile(r'picoCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', re.IGNORECASE)

print('--- run 626a4b96 ---')
print('status :', row['status'])
print('flag   :', row['flag'])
print('url    :', ch.get('url'))
print('steps  :', len(steps))
print()

ev_counts = Counter(s.get('event', '') for s in steps)
for ev, cnt in ev_counts.most_common():
    print(f'  {ev}: {cnt}')
print()

for s in steps:
    ev = s.get('event', '')
    nid = s.get('node_id', '')
    d = s.get('data') or {}
    flag_hit = flag_re.search(json.dumps(s))
    marker = ' ***FLAG***' if flag_hit else ''
    print(f"[{s.get('step','?'):3}] {ev:22} | {nid}{marker}")
    if ev in ('exploit_result', 'flag_found') or flag_hit:
        for k, v in d.items():
            print(f'       {k}: {str(v)[:350]}')
