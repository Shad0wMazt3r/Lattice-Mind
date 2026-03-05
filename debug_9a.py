import json, sqlite3, re
conn = sqlite3.connect('/data/runs.db')
conn.row_factory = sqlite3.Row
row = conn.execute(
    "SELECT run_id,status,flag,created_at,finished_at,steps,challenge FROM runs WHERE run_id LIKE '9a82fad0%'"
).fetchone()
steps = json.loads(row['steps'] or '[]')
flag_re = re.compile(r'picoCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}', re.IGNORECASE)
print('run_id:', row['run_id'])
print('status:', row['status'])
print('flag:', row['flag'])
print('total steps:', len(steps))
ch = json.loads(row['challenge'] or '{}')
print('url:', ch.get('url'))
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
            print(f'       {k}: {str(v)[:300]}')
