import threading
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, make_response
import db, scanner

app = Flask(__name__)
db.init()

def stats(findings):
    c = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c

@app.route("/")
def index():
    return render_template("index.html", scans=db.list_scans(5), error=request.args.get("error"))

@app.post("/scan")
def start_scan():
    url = request.form.get("url", "").strip()
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        return redirect(url_for("index", error="Дұрыс URL енгізіңіз (http:// немесе https://)"))
    if not request.form.get("authorized"):
        return redirect(url_for("index", error="Сканерлеуге рұқсатыңыз бар екенін растаңыз"))
    sid = db.create_scan(url)
    threading.Thread(target=scanner.run_scan, args=(sid, url), daemon=True).start()
    return redirect(url_for("scan_view", sid=sid))

@app.route("/scan/<int:sid>")
def scan_view(sid):
    scan = db.get_scan(sid) or abort(404)
    f = db.get_findings(sid)
    return render_template("scan.html", scan=scan, findings=f, counts=stats(f))

@app.route("/api/scan/<int:sid>")
def scan_api(sid):
    scan = db.get_scan(sid) or abort(404)
    return jsonify(status=scan["status"], progress=scan["progress"])

@app.route("/scan/<int:sid>/report")
def report(sid):
    scan = db.get_scan(sid) or abort(404)
    f = db.get_findings(sid)
    resp = make_response(render_template("report.html", scan=scan, findings=f, counts=stats(f)))
    resp.headers["Content-Disposition"] = f"attachment; filename=report_{sid}.html"
    return resp

@app.route("/history")
def history():
    return render_template("history.html", scans=db.list_scans())

if __name__ == "__main__":
    app.run(debug=False)
