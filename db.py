import sqlite3, datetime

DB = "scanner.db"

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL, status TEXT NOT NULL, progress TEXT DEFAULT '',
            created TEXT NOT NULL, finished TEXT);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL, title TEXT, owasp TEXT, severity TEXT,
            url TEXT, evidence TEXT, fix TEXT);
        """)

def create_scan(url):
    with conn() as c:
        cur = c.execute("INSERT INTO scans(url,status,created) VALUES(?,?,?)",
                        (url, "running", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        return cur.lastrowid

def update_scan(sid, **kw):
    keys = ", ".join(f"{k}=?" for k in kw)
    with conn() as c:
        c.execute(f"UPDATE scans SET {keys} WHERE id=?", (*kw.values(), sid))

def add_findings(sid, items):
    with conn() as c:
        c.executemany(
            "INSERT INTO findings(scan_id,title,owasp,severity,url,evidence,fix) VALUES(?,?,?,?,?,?,?)",
            [(sid, f["title"], f["owasp"], f["severity"], f["url"], f["evidence"], f["fix"]) for f in items])

def get_scan(sid):
    with conn() as c:
        return c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()

def list_scans(limit=50):
    with conn() as c:
        return c.execute(
            """SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS total
               FROM scans s ORDER BY s.id DESC LIMIT ?""", (limit,)).fetchall()

def get_findings(sid):
    order = "CASE severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END"
    with conn() as c:
        return c.execute(f"SELECT * FROM findings WHERE scan_id=? ORDER BY {order}, owasp", (sid,)).fetchall()
