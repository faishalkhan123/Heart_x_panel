"""
Hunter Arena - Test data wipe server

  GET  /wipe           -> owner login (browser popup) ke baad page: "DELETE ALL DATA" button
  POST /api/wipe/all   -> owner login + {"confirm": "DELETE ALL DATA"} -> poora Firebase database delete
  GET|POST /alive      -> "yes"

Owner username/password wahi env se jo baaki servers me hain (OWNER_USERNAME, OWNER_PASSWORD).
Firebase env bhi wahi (FIREBASE_DATABASE_URL + FIREBASE_DATABASE_SECRET ya service account).

WARNING: ye database ka SAARA data delete karta hai (users, wallet, matches, withdrawals, admins).
Wapas nahi aata. Jis Firebase project pe env point karta hai usi ka data jayega.

Render start command:  gunicorn app:app --workers 1 --threads 4
"""
import base64
import hmac
import logging
import os
import threading
import time

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("wipe")

OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "").strip().lower()
OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD", "")
if not OWNER_USERNAME or not OWNER_PASSWORD:
    raise RuntimeError("Env me OWNER_USERNAME aur OWNER_PASSWORD set karo")

CONFIRM_TEXT = "DELETE ALL DATA"
FAIL_MAX = 5           # galat login itni baar ke baad lock
FAIL_LOCK = 600        # 10 minute lock
PING_EVERY = 300

SERVERS = [
    "https://fk-games.onrender.com",
    "https://hunter-turnament.onrender.com",
    "https://withdrawal-uvtk.onrender.com",
    "https://hunter-arena.onrender.com",
    "https://anda-patanahihaigghshsdh.onrender.com",
]
SCOPES = [
    "https://www.googleapis.com/auth/firebase.database",
    "https://www.googleapis.com/auth/userinfo.email",
]


# ─────────────── Firebase (sirf delete ke liye) ───────────────
class Firebase:
    def __init__(self):
        self.base = os.environ.get("FIREBASE_DATABASE_URL", "").strip().rstrip("/")
        if not self.base:
            raise RuntimeError("Env variable FIREBASE_DATABASE_URL set karo")
        self.http = requests.Session()
        self.lock = threading.Lock()
        self.creds = None
        self.secret = None
        mail = os.environ.get("FIREBASE_CLIENT_EMAIL", "").strip()
        key = os.environ.get("FIREBASE_PRIVATE_KEY", "").strip().strip('"').replace("\\n", "\n")
        if mail and key:
            from google.oauth2 import service_account
            info = {"type": "service_account", "client_email": mail, "private_key": key,
                    "token_uri": "https://oauth2.googleapis.com/token"}
            kid = os.environ.get("FIREBASE_PRIVATE_KEY_ID", "").strip()
            if kid:
                info["private_key_id"] = kid
            self.creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
        else:
            self.secret = os.environ.get("FIREBASE_DATABASE_SECRET", "").strip()
            if not self.secret:
                raise RuntimeError("Env me FIREBASE_DATABASE_SECRET ya "
                                   "(FIREBASE_CLIENT_EMAIL + FIREBASE_PRIVATE_KEY) set karo")

    def _auth(self):
        if self.secret:
            return {"auth": self.secret}, {}
        with self.lock:
            if not self.creds.valid:
                from google.auth.transport.requests import Request
                self.creds.refresh(Request())
            return {}, {"Authorization": "Bearer " + self.creds.token}

    def wipe_root(self):
        """Poora database delete. URL me secret nahi jata, error me bhi nahi."""
        params, hdrs = self._auth()
        try:
            r = self.http.delete(f"{self.base}/.json", params=params, headers=hdrs, timeout=60)
        except requests.RequestException as e:
            raise RuntimeError(f"Firebase delete failed: {type(e).__name__}") from None
        if r.status_code != 200:
            raise RuntimeError(f"Firebase delete returned HTTP {r.status_code}")


fb = Firebase()
app = Flask(__name__)
FAILS = {}


# ───────────────────────── owner login (Basic auth) ─────────────────────────
def locked(ip):
    now = time.time()
    recent = [t for t in FAILS.get(ip, []) if now - t < FAIL_LOCK]
    FAILS[ip] = recent
    return len(recent) >= FAIL_MAX


def client_ip():
    ip = request.headers.get("True-Client-IP") or request.headers.get("CF-Connecting-IP")
    if not ip:
        xff = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        ip = xff[-2] if len(xff) >= 2 else (xff[0] if xff else request.remote_addr)
    return (ip or "unknown").strip()[:64]


def owner_ok():
    """Browser ka Basic-auth popup = owner username + password. Galat ho to 401."""
    ip = client_ip()
    if locked(ip):
        return None, ("Too many wrong attempts. Try again after 10 minutes", 429)
    auth = request.headers.get("Authorization", "")
    user = pwd = ""
    if auth.lower().startswith("basic "):
        try:
            user, _, pwd = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
        except Exception:
            user = pwd = ""
    user_ok = hmac.compare_digest(user.strip().lower().encode(), OWNER_USERNAME.encode())
    pass_ok = hmac.compare_digest(pwd.encode(), OWNER_PASSWORD.encode())
    if user_ok and pass_ok:
        return ip, None
    FAILS.setdefault(ip, []).append(time.time())
    return None, ("Owner login required", 401)


def unauthorized(message, code):
    resp = Response(message, status=code, mimetype="text/plain")
    if code == 401:
        resp.headers["WWW-Authenticate"] = 'Basic realm="Hunter Arena wipe", charset="UTF-8"'
    return resp


# ───────────────────────── routes ─────────────────────────
@app.route("/alive", methods=["GET", "POST"])
def alive():
    return Response("yes", mimetype="text/plain")


@app.get("/")
def home():
    return jsonify({"ok": True, "service": "wipe"})


@app.get("/wipe")
def wipe_page():
    _, failure = owner_ok()
    if failure:
        return unauthorized(failure[0], failure[1])
    resp = Response(WIPE_HTML.replace("__CONFIRM__", CONFIRM_TEXT), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/wipe/all")
def wipe_all():
    _, failure = owner_ok()
    if failure:
        return jsonify({"ok": False, "error": failure[0]}), failure[1]
    data = request.get_json(force=True, silent=True) or {}
    if str(data.get("confirm") or "") != CONFIRM_TEXT:
        return jsonify({"ok": False, "error": f"Type exactly: {CONFIRM_TEXT}"}), 400
    try:
        fb.wipe_root()
    except RuntimeError as e:
        log.error("wipe failed: %s", e)
        return jsonify({"ok": False, "error": "Wipe failed. Check Render logs."}), 500
    log.warning("ALL DATA WIPED by owner")
    return jsonify({"ok": True, "message": "Poora database delete ho gaya. Ab sab servers restart karo."})


WIPE_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hunter Arena - Wipe test data</title>
<style>
body{margin:0;background:#0b1020;color:#eaf0ff;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
.box{max-width:520px;margin:30px auto;background:#141b34;border:1px solid #7f1d2d;border-radius:16px;padding:18px}
h2{margin:0 0 8px;color:#fca5a5}
p{color:#98a4cf}
input{width:100%;padding:12px;border-radius:10px;border:1px solid #26305a;background:#0a1030;color:#fff;font-size:16px;margin-top:8px}
button{width:100%;margin-top:12px;padding:14px;border:0;border-radius:12px;background:#b91c1c;color:#fff;font-weight:800;font-size:16px}
button:disabled{background:#3a1520;color:#94a3b8}
.msg{margin-top:12px;min-height:1.3em}.ok{color:#86efac}.bad{color:#fca5a5}
</style></head>
<body>
<div class="box">
  <h2>DANGER: Delete ALL data</h2>
  <p>Ye database ka saara data delete karega: users, wallet, matches, withdrawals, admins, sab. Wapas nahi aayega.
     Pehle Firebase Console se backup le lo (Realtime Database &gt; ⋮ &gt; Export JSON).</p>
  <p>Confirm karne ke liye neeche <b>__CONFIRM__</b> likho:</p>
  <input id="t" autocomplete="off" placeholder="__CONFIRM__">
  <button id="b" disabled>DELETE ALL DATA</button>
  <div class="msg" id="m"></div>
</div>
<script>
(function () {
  var CONFIRM = "__CONFIRM__";
  var t = document.getElementById('t'), b = document.getElementById('b'), m = document.getElementById('m');
  t.addEventListener('input', function () { b.disabled = t.value.trim() !== CONFIRM; });
  b.addEventListener('click', function () {
    if (!confirm('Last warning: poora database delete hoga. Pakka?')) return;
    b.disabled = true; m.className = 'msg'; m.textContent = 'Deleting...';
    fetch('/api/wipe/all', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirm: CONFIRM }) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { r: r, j: j }; }); })
      .then(function (x) {
        if (x.r.ok && x.j.ok) { m.className = 'msg ok'; m.textContent = x.j.message; }
        else { m.className = 'msg bad'; m.textContent = x.j.error || ('HTTP ' + x.r.status); b.disabled = false; }
      })
      .catch(function () { m.className = 'msg bad'; m.textContent = 'Network error'; b.disabled = false; });
  });
})();
</script>
</body></html>
"""


# ───────────────────────── keep-alive pinger ─────────────────────────
def ping_all():
    for base in SERVERS:
        url = base.rstrip("/") + "/alive"
        try:
            r = requests.get(url, timeout=30, headers={"User-Agent": "alive-check"})
            log.info("ping %s -> %s %r", url, r.status_code, r.text.strip()[:20])
        except requests.RequestException as e:
            log.warning("ping %s failed (%s)", url, type(e).__name__)


def ping_loop():
    while True:
        try:
            ping_all()
        except Exception:
            log.exception("ping loop error")
        time.sleep(PING_EVERY)


def start_jobs():
    threading.Thread(target=ping_loop, daemon=True, name="alive-pinger").start()


start_jobs()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
          
