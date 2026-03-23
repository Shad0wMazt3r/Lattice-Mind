import sqlite3, json
rid='60d110a3'
con=sqlite3.connect('/data/runs.db')
cur=con.cursor()
cur.execute("SELECT run_id,status,challenge,log,observations,steps FROM runs WHERE run_id LIKE ? ORDER BY created_at DESC LIMIT 1", (rid+'%',))
row=cur.fetchone()
print('ROW_FOUND', bool(row))
if row:
    print('RUN', row[0], row[1])
    ch=json.loads(row[2] or '{}')
    print('URL', ch.get('url'))
    lg=json.loads(row[3] or '{}')
    obs=lg.get('observations') or json.loads(row[4] or '{}')
    cg=obs.get('crawl_graph') or []
    print('CRAWL_NODES', len(cg))
    print('CRAWL_STATS', obs.get('crawl_stats'))
    print('FORMS', len(obs.get('forms') or []))
    print('REQ_CANDS', len(obs.get('request_candidates') or []))
    for n in cg[:15]:
        print('NODE', n.get('id'), n.get('url'), n.get('discovered_via'), n.get('status_code'))
        if n.get('forms'):
            print('  NODE_FORMS', len(n.get('forms') or []), [f.get('method')+':'+(f.get('action') or '') for f in (n.get('forms') or [])][:3])
    st=json.loads(row[5] or '[]')
    print('STEPS', len(st))
    for s in st[-15:]:
        print('STEP', s.get('event'), s.get('node_name'), s.get('status'))
con.close()
