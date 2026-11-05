"""OWASP Top 10 (2021) негізіндегі қарапайым, зиянсыз (non-destructive) сканер."""
import re, secrets
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import db

TIMEOUT = 8
MAX_PAGES = 15
HEADERS = {"User-Agent": "OWASP-EduScanner/1.0 (educational)"}

# ---------- Түзету бойынша ұсыныстар ----------
FIX = {
    "csp": "Content-Security-Policy тақырыбын қосыңыз, мысалы: default-src 'self'. Бұл XSS қаупін азайтады.",
    "xfo": "X-Frame-Options: DENY (немесе CSP frame-ancestors) орнатыңыз — clickjacking-тен қорғайды.",
    "xcto": "X-Content-Type-Options: nosniff тақырыбын қосыңыз.",
    "hsts": "HTTPS сайтқа Strict-Transport-Security: max-age=31536000; includeSubDomains қосыңыз.",
    "refpol": "Referrer-Policy: strict-origin-when-cross-origin (немесе қатаң) орнатыңыз.",
    "secure": "Cookie-ге Secure атрибутын қойыңыз — тек HTTPS арқылы жіберіледі.",
    "httponly": "Сессия cookie-іне HttpOnly қойыңыз — JavaScript оқи алмайды.",
    "samesite": "Cookie-ге SameSite=Lax немесе Strict қойыңыз — CSRF қаупін азайтады.",
    "xss": "Шығыс деректерін контекст бойынша экрандаңыз (HTML-escape), шаблон қозғалтқышының autoescape-ін қосыңыз, CSP қолданыңыз.",
    "sqli": "Параметрленген сұраныстарды (prepared statements) немесе ORM қолданыңыз; SQL жолдарын қолмен біріктірмеңіз; қате мәтінін пайдаланушыға көрсетпеңіз.",
    "file": "Бұл файлды веб-түбірден алып тастаңыз немесе сервер конфигурациясында қолжетімділікті жабыңыз. Ашылып қалған құпияларды (кілттер, құпия сөздер) ауыстырыңыз.",
    "dirlist": "Веб-серверде directory listing-ті өшіріңіз (Apache: Options -Indexes; Nginx: autoindex off).",
}

def F(title, owasp, sev, url, evidence, fix):
    return dict(title=title, owasp=owasp, severity=sev, url=url, evidence=evidence, fix=FIX[fix])

# ---------- Crawler ----------
def crawl(start, session, log):
    host = urlparse(start).netloc
    queue, seen, pages, targets = [start], set(), [], []
    seen_t = set()
    while queue and len(pages) < MAX_PAGES:
        url = queue.pop(0).split("#")[0]
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        log(f"Бет оқылды: {url}")
        pages.append((url, r))
        if "text/html" not in r.headers.get("Content-Type", ""):
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if urlparse(link).netloc == host and link.startswith("http"):
                if urlparse(link).query:
                    base = link.split("?")[0]
                    params = {k: v[0] if v else "" for k, v in
                              __import__("urllib.parse").parse.parse_qs(urlparse(link).query, keep_blank_values=True).items()}
                    key = ("GET", base, tuple(sorted(params)))
                    if key not in seen_t:
                        seen_t.add(key)
                        targets.append(dict(method="GET", url=base, params=params))
                queue.append(link)
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            if urlparse(action).netloc != host:
                continue
            method = (form.get("method") or "get").upper()
            params = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                typ = (inp.get("type") or "text").lower()
                if name and typ not in ("submit", "button", "file", "image", "password"):
                    params[name] = inp.get("value") or "test"
            if params:
                key = (method, action, tuple(sorted(params)))
                if key not in seen_t:
                    seen_t.add(key)
                    targets.append(dict(method=method, url=action, params=params))
    return pages, targets

# ---------- Тексерулер ----------
def check_headers(pages):
    out, done = [], set()
    for url, r in pages[:1]:
        h = {k.lower(): v for k, v in r.headers.items()}
        csp = "content-security-policy" in h
        rules = [
            (csp, "Content-Security-Policy жоқ", "Medium", "csp"),
            ("x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", ""),
             "X-Frame-Options жоқ", "Medium", "xfo"),
            ("x-content-type-options" in h, "X-Content-Type-Options жоқ", "Low", "xcto"),
            ("referrer-policy" in h, "Referrer-Policy жоқ", "Low", "refpol"),
        ]
        if url.startswith("https"):
            rules.append(("strict-transport-security" in h, "HSTS жоқ", "Medium", "hsts"))
        for ok, title, sev, fx in rules:
            if not ok:
                out.append(F(title, "A05:2021 Security Misconfiguration", sev, url,
                             "Жауап тақырыбында табылмады", fx))
    return out

def check_cookies(session, pages):
    out, seen = [], set()
    for url, r in pages:
        for raw in r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw.headers, "getlist") else []:
            name = raw.split("=")[0].strip()
            if name in seen:
                continue
            seen.add(name)
            low = raw.lower()
            if url.startswith("https") and "secure" not in low:
                out.append(F(f"Cookie '{name}': Secure жоқ", "A02:2021 Cryptographic Failures", "Medium", url, raw[:120], "secure"))
            if "httponly" not in low:
                out.append(F(f"Cookie '{name}': HttpOnly жоқ", "A05:2021 Security Misconfiguration", "Medium", url, raw[:120], "httponly"))
            if "samesite" not in low:
                out.append(F(f"Cookie '{name}': SameSite жоқ", "A01:2021 Broken Access Control", "Low", url, raw[:120], "samesite"))
    return out

def _send(session, t, params):
    if t["method"] == "POST":
        return session.post(t["url"], data=params, timeout=TIMEOUT)
    return session.get(t["url"], params=params, timeout=TIMEOUT)

def check_xss(session, targets):
    out = []
    for t in targets:
        for name in t["params"]:
            m = "xs" + secrets.token_hex(3)
            params = dict(t["params"]); params[name] = f'{m}"><{m}x>'
            try:
                r = _send(session, t, params)
            except requests.RequestException:
                continue
            if f"<{m}x>" in r.text:
                out.append(F(f"Reflected XSS (параметр: {name})", "A03:2021 Injection", "High", t["url"],
                             "Зиянсыз маркер HTML-де экрандалмай шықты", "xss"))
                break
    return out

SQL_ERRORS = re.compile(
    r"you have an error in your sql syntax|warning: mysql|mysqli?_|unclosed quotation mark|"
    r"sqlite3?\.operationalerror|sqlite error|sqlstate\[|pg_query|psql:|ora-\d{5}|"
    r"syntax error at or near|odbc .* driver|quoted string not properly terminated", re.I)

def check_sqli(session, targets):
    out = []
    for t in targets:
        try:
            base = _send(session, t, t["params"]).text
        except requests.RequestException:
            continue
        for name in t["params"]:
            params = dict(t["params"]); params[name] = t["params"][name] + "'"
            try:
                r = _send(session, t, params)
            except requests.RequestException:
                continue
            m = SQL_ERRORS.search(r.text)
            if m and not SQL_ERRORS.search(base):
                out.append(F(f"Error-based SQL Injection (параметр: {name})", "A03:2021 Injection", "High", t["url"],
                             f"SQL қате белгісі: {m.group(0)[:80]}", "sqli"))
                break
    return out

SENSITIVE = [  # (жол, қолтаңба)
    ("/.git/HEAD", "ref:"), ("/.env", "="), ("/phpinfo.php", "phpinfo"),
    ("/.DS_Store", "Bud1"), ("/WEB-INF/web.xml", "<web-app"),
    ("/config.php.bak", "<?php"), ("/backup.sql", "INSERT INTO"), ("/server-status", "Apache Server Status"),
]
DIRS = ["/uploads/", "/backup/", "/images/", "/files/", "/logs/"]

def check_files(session, base):
    out = []
    for path, sig in SENSITIVE:
        try:
            r = session.get(base + path, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and sig.lower() in r.text.lower():
            out.append(F(f"Құпия файл ашық: {path}", "A05:2021 Security Misconfiguration", "High",
                         base + path, "HTTP 200 және файл қолтаңбасы табылды", "file"))
    for d in DIRS:
        try:
            r = session.get(base + d, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and re.search(r"<title>Index of /", r.text, re.I):
            out.append(F(f"Directory listing қосулы: {d}", "A05:2021 Security Misconfiguration", "Medium",
                         base + d, "'Index of /' беті табылды", "dirlist"))
    return out

# ---------- Негізгі іске қосу ----------
def run_scan(sid, start):
    def log(msg): db.update_scan(sid, progress=msg)
    try:
        s = requests.Session(); s.headers.update(HEADERS)
        p = urlparse(start); base = f"{p.scheme}://{p.netloc}"
        log("Crawler жұмыс істеп тұр...")
        pages, targets = crawl(start, s, log)
        if not pages:
            raise RuntimeError("Сайтқа қосылу мүмкін болмады")
        findings = []
        for label, fn in [
            ("Тақырыптар тексерілуде", lambda: check_headers(pages)),
            ("Cookie тексерілуде", lambda: check_cookies(s, pages)),
            ("XSS тексерілуде", lambda: check_xss(s, targets)),
            ("SQLi тексерілуде", lambda: check_sqli(s, targets)),
            ("Ашық файлдар тексерілуде", lambda: check_files(s, base)),
        ]:
            log(label); findings += fn()
        db.add_findings(sid, findings)
        db.update_scan(sid, status="done", progress=f"Дайын: {len(pages)} бет, {len(targets)} енгізу нүктесі",
                       finished=__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as e:
        db.update_scan(sid, status="error", progress=f"Қате: {e}")
