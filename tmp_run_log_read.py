import sqlite3, json
rid='60d110a3'
con=sqlite3.connect('/data/runs.db')
cur=con.cursor()
cur.execute("SELECT log FROM runs WHERE run_id LIKE ? ORDER BY created_at DESC LIMIT 1", (rid+'%',))
row=cur.fetchone()
lg=json.loads((row[0] if row else '{}') or '{}')
obs=(lg.get('observations') or {})
print('OBS_KEYS', sorted(obs.keys()))
print('FORMS_SAMPLE', (obs.get('forms') or [])[:2])
print('REQ_CANDS_SAMPLE', (obs.get('request_candidates') or [])[:2])
print('CRAWL_GRAPH_SAMPLE', (obs.get('crawl_graph') or [])[:2])
con.close()
