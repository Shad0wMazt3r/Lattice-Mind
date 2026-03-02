import sqlite3
import json

try:
    conn = sqlite3.connect('C:/data/runs.db')
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM runs").fetchall()
    print(json.dumps([dict(r) for r in rows], indent=2))
except Exception as e:
    print(f"Error: {e}")
