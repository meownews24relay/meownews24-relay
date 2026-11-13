#!/usr/bin/env python3
"""MeowNews24 image relay server (v36) — Muse <-> bot image relay.

A tiny dependency-free HTTP server (Python stdlib only) that lets the bot
and Muse pass slot images back and forth WITHOUT the user sending photos
in Telegram by hand:

  bot  --POST /relay/request-->  relay  --GET /relay/pending-->  Muse
  Muse --POST /relay/deliver-->  relay  --GET /relay/delivered--> bot
  bot  --GET /relay/image/<slot>--> relay (downloads the image bytes)

v45 — HTTP COMMAND channel (the fix for Telegram bot-to-bot invisibility:
Telegram NEVER delivers bot-to-bot messages, so the relay-group text
commands can never reach the main bot). Muse POSTs a command, the bot
polls for it and executes it, then reports the outcome:

  Muse --POST /relay/command--> relay --GET /relay/command--> bot
  bot  --POST /relay/command_result--> relay --GET /relay/command_result--> Muse
  (the bot also posts the same detailed "🤖 Muse →" confirmation in the
  relay group, so the user sees every command's outcome there too)

WHY A SERVER (and not the phone/VM directly)?
  * This VM is NOT reachable from the internet (behind CGNAT NAT; its
    public IP is not bound to any local interface; Tailscale is client-only
    and accepts no inbound). The phone therefore CANNOT reach a server on
    this VM. The relay must run on a host the phone CAN reach.
  * No-signup public stores were verified UNUSABLE from here: kvdb.io now
    requires a verified email (a placeholder email is rejected with 403);
    jsonblob.com is Cloudflare-blocked (403); 0x0.st uploads are disabled
    (503); catbox.moe is unreachable from this VM. So there is no free
    anonymous store to fall back on — the relay is self-hosted.
  * This server is therefore the relay: run it on any host the phone can
    reach (a cheap VPS, a free PaaS, or behind a tunnel), set the bot's
    relay URL to it (Telegram: /relayurl <url>), and set RELAY_SECRET to
    the bot's relay secret (shown in the bot's Auto Post menu -> Relay).

v47 — SECRET AUTO-REGISTRATION: the user could not find the relay secret
on the bot's Relay card, so the bot now POSTs its own secret to
POST /relay/register (no auth) on startup and the server stores it
(relay_state.json, key "bot_secret"). Later requests validate against
the registered secret; RELAY_SECRET / relay_secret.txt remain as a
manual fallback (registered wins). The user only ever sends
/relayurl <url> once — the secret step is gone.

v4 — HOSTED AUTH FIX (Render/PaaS): on a self-hosted VM Muse reads the
registered secret from relay_state.json, but on a PaaS she cannot read
the host filesystem. So _auth_ok now accepts EITHER the bot-registered
secret OR the env/file secret (RELAY_SECRET, set by Muse at deploy
time). The bot registers its own secret and uses it; Muse uses the env
secret she set. Both are random and known only to an authorised party.
Without this fix a hosted relay would be unusable for Muse (she would
have no way to learn the bot's registered secret).

AUTH: every endpoint except /relay/health and /relay/register requires
  the header X-Relay-Secret: <secret>
The secret is shared out-of-band: the bot auto-generates it once and stores
it in its data file (meownews_master_data.json, NEVER in code). v47: the
bot registers its own secret itself (POST /relay/register, no auth), so
the user never has to find/send it; RELAY_SECRET / relay_secret.txt stay
as a manual fallback (registered wins). A wrong secret gets 401 and
nothing is read or written. The secret value is never logged or echoed.
v4 (hosted): _auth_ok accepts EITHER the registered secret OR the
env/file secret, so Muse (who sets RELAY_SECRET at deploy time but
cannot read a PaaS host's filesystem) can still authenticate after the
bot registers. See the v4 note above.

PERSISTENCE: requests + delivery metadata live in relay_state.json and
images in images/<slot>.jpg under the data dir (default
~/workspace/meownews24-relay/data). Entries older than 48h are pruned.
Restarting the server loses nothing; the data dir survives VM replacement
because it lives under ~/workspace.

RUN (local test):
  RELAY_SECRET=test-secret python3 relay_server.py --host 127.0.0.1 --port 8765
RUN (production, behind TLS):
  RELAY_SECRET=<bot-secret> python3 relay_server.py --host 0.0.0.0 --port 8765
  (put it behind Caddy/nginx with TLS, or on a PaaS that provides HTTPS;
  plain HTTP over the public internet would expose the secret header.)
  RELAY_SECRET is optional when a secret was already registered — the
  server then starts and validates against the registered secret.
SYSTEMD (persistent): see meownews24-relay.service in this folder.
"""

import argparse
import base64
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = 4
PRUNE_AFTER_HOURS = 48
CMD_KINDS = {"menu", "series", "numbered", "review"}
CMD_HISTORY_MAX = 10
CMD_RESULT_MAX = 20
SLOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
IMAGE_MAGIC = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"RIFF", "image/webp"),  # WebP: RIFF....WEBP (checked below)
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(s):
    try:
        return datetime.fromisoformat(str(s))
    except Exception:
        return None


def _sniff_image(data):
    """Return a content-type if data looks like an image, else None."""
    if not data:
        return None
    for magic, ctype in IMAGE_MAGIC:
        if data.startswith(magic):
            if ctype == "image/webp":
                if len(data) >= 12 and data[8:12] == b"WEBP":
                    return ctype
                return None
            return ctype
    return None


class RelayStore:
    """Thread-safe JSON state + image files."""

    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.img_dir = self.dir / "images"
        self.img_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.dir / "relay_state.json"
        self.lock = threading.Lock()
        self.state = {"requests": {}, "deliveries": {},
                      "commands": {}, "pending_command_id": None,
                      "command_results": {}, "bot_secret": ""}
        self._load()

    def _load(self):
        try:
            if self.state_file.exists():
                raw = json.loads(self.state_file.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self.state["requests"] = raw.get("requests") or {}
                    self.state["deliveries"] = raw.get("deliveries") or {}
                    # v45: HTTP command queue (single pending + history).
                    self.state["commands"] = raw.get("commands") or {}
                    self.state["pending_command_id"] = raw.get("pending_command_id")
                    self.state["command_results"] = raw.get("command_results") or {}
                    # v47: bot auto-registered secret.
                    self.state["bot_secret"] = str(raw.get("bot_secret") or "")
        except Exception:
            self.state = {"requests": {}, "deliveries": {},
                          "commands": {}, "pending_command_id": None,
                          "command_results": {}, "bot_secret": ""}

    def _save(self):
        try:
            tmp = self.state_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.state, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.state_file)
        except Exception:
            pass

    def _prune(self):
        cutoff = datetime.now(timezone.utc) - timedelta(hours=PRUNE_AFTER_HOURS)
        changed = False
        for slot in list(self.state["requests"]):
            ts = _parse_iso((self.state["requests"][slot] or {}).get("requested_at") or "")
            if ts and ts < cutoff:
                self.state["requests"].pop(slot, None)
                changed = True
        for slot in list(self.state["deliveries"]):
            ts = _parse_iso((self.state["deliveries"][slot] or {}).get("delivered_at") or "")
            if ts and ts < cutoff:
                self.state["deliveries"].pop(slot, None)
                changed = True
                try:
                    p = self.img_dir / (slot + ".jpg")
                    if p.exists():
                        p.unlink()
                except Exception:
                    pass
        # v45: prune the command queue + results the same way (48h).
        for cid in list((self.state.get("commands") or {})):
            ts = _parse_iso(((self.state.get("commands") or {}).get(cid) or {}).get("created_at") or "")
            if ts and ts < cutoff:
                (self.state.get("commands") or {}).pop(cid, None)
                changed = True
                if self.state.get("pending_command_id") == cid:
                    self.state["pending_command_id"] = None
        for cid in list((self.state.get("command_results") or {})):
            ts = _parse_iso(((self.state.get("command_results") or {}).get(cid) or {}).get("reported_at") or "")
            if ts and ts < cutoff:
                (self.state.get("command_results") or {}).pop(cid, None)
                changed = True
        if changed:
            self._save()

    # ---------------- v45: HTTP command queue ----------------
    def add_command(self, cmd):
        """Validate + store one command. It becomes THE pending command
        (any older unclaimed one is superseded — it stays in history but
        is never returned again). Keeps the last CMD_HISTORY_MAX commands.
        Returns the new command id, or None when the body is invalid.
        Never logs or echoes the secret (the secret is never in a command)."""
        with self.lock:
            self._prune()
            if not isinstance(cmd, dict):
                return None
            kind = str(cmd.get("kind") or "").strip().lower()
            if kind not in CMD_KINDS:
                return None
            if kind == "menu" and not str(cmd.get("number") or "").strip():
                return None
            if kind == "series" and not str(cmd.get("text") or "").strip():
                return None
            if kind == "numbered" and (not str(cmd.get("number") or "").strip()
                                       or not str(cmd.get("slot") or "").strip()):
                return None
            if kind == "review" and (not str(cmd.get("word") or "").strip()
                                     or not str(cmd.get("draft_id") or "").strip()):
                return None
            cid = "cmd-%d-%s" % (int(time.time()), secrets.token_hex(4))
            rec = dict(cmd)
            rec["kind"] = kind
            rec["id"] = cid
            rec["created_at"] = _now_iso()
            rec["claimed"] = False
            rec["claimed_at"] = ""
            cmds = self.state.setdefault("commands", {})
            cmds[cid] = rec
            self.state["pending_command_id"] = cid
            # History cap: keep the last CMD_HISTORY_MAX (never drop the pending one).
            if len(cmds) > CMD_HISTORY_MAX:
                ordered = sorted(cmds.values(), key=lambda r: str(r.get("created_at") or ""))
                for old in ordered:
                    if len(cmds) <= CMD_HISTORY_MAX:
                        break
                    if str(old.get("id")) == cid:
                        continue
                    cmds.pop(str(old.get("id")), None)
            self._save()
            return cid

    def claim_command(self):
        """Return the pending command (cleaned: id + kind + fields, no
        internal flags) and mark it claimed so it is never returned again.
        Returns None when nothing is pending. The pending id is cleared."""
        with self.lock:
            self._prune()
            cid = self.state.get("pending_command_id")
            if not cid:
                return None
            rec = (self.state.get("commands") or {}).get(str(cid))
            if not isinstance(rec, dict) or rec.get("claimed"):
                self.state["pending_command_id"] = None
                self._save()
                return None
            rec["claimed"] = True
            rec["claimed_at"] = _now_iso()
            self.state["pending_command_id"] = None
            self._save()
            out = {k: v for k, v in rec.items() if k not in ("claimed", "claimed_at")}
            return out

    def add_command_result(self, res):
        """Store one command outcome. Keeps the last CMD_RESULT_MAX results.
        Returns True only when stored (id required)."""
        with self.lock:
            self._prune()
            if not isinstance(res, dict):
                return False
            cid = str(res.get("id") or "").strip()
            if not cid:
                return False
            rec = {"id": cid, "ok": bool(res.get("ok")),
                   "result": str(res.get("result") or "")[:500],
                   "reported_at": _now_iso()}
            results = self.state.setdefault("command_results", {})
            results[cid] = rec
            if len(results) > CMD_RESULT_MAX:
                ordered = sorted(results.values(), key=lambda r: str(r.get("reported_at") or ""))
                for old in ordered:
                    if len(results) <= CMD_RESULT_MAX:
                        break
                    results.pop(str(old.get("id")), None)
            self._save()
            return True

    def command_result(self, cmd_id):
        """Return one stored result, or the MOST RECENT result when no id
        is given. Returns None when there is no matching result."""
        with self.lock:
            self._prune()
            results = self.state.get("command_results") or {}
            if cmd_id:
                return results.get(str(cmd_id))
            if not results:
                return None
            ordered = sorted(results.values(), key=lambda r: str(r.get("reported_at") or ""))
            return ordered[-1] if ordered else None

    # ---------------- v47: bot secret auto-registration ----------------
    def register_secret(self, secret):
        """Store the bot's own secret (auto-registration via
        POST /relay/register). Overwrites any previous registered secret
        (the bot re-registers the same secret on every restart; overwrite
        keeps a rotated secret working). Returns True. Never logs the
        secret value."""
        with self.lock:
            self.state["bot_secret"] = str(secret)
            self._save()
            return True

    def registered_secret(self):
        """The bot auto-registered secret, or '' when none is stored."""
        with self.lock:
            return str(self.state.get("bot_secret") or "")

    def add_request(self, req):
        with self.lock:
            self._prune()
            slot = str(req.get("slot") or "")
            if not SLOT_RE.match(slot):
                return False
            req = dict(req)
            req.setdefault("requested_at", _now_iso())
            self.state["requests"][slot] = req
            self._save()
            return True

    def pending(self):
        with self.lock:
            self._prune()
            delivered = set(self.state["deliveries"])
            out = [r for s, r in self.state["requests"].items() if s not in delivered]
            out.sort(key=lambda r: str(r.get("requested_at") or ""))
            return out

    def deliver_bytes(self, slot, data, content_type):
        with self.lock:
            self._prune()
            if not SLOT_RE.match(slot):
                return False
            try:
                p = self.img_dir / (slot + ".jpg")
                p.write_bytes(data)
            except Exception:
                return False
            self.state["deliveries"][slot] = {
                "slot": slot, "stored": True, "content_type": content_type,
                "delivered_at": _now_iso(), "image_url": None,
            }
            self._save()
            return True

    def deliver_url(self, slot, url):
        with self.lock:
            self._prune()
            if not SLOT_RE.match(slot):
                return False
            if not str(url).startswith(("http://", "https://")):
                return False
            self.state["deliveries"][slot] = {
                "slot": slot, "stored": False, "content_type": "",
                "delivered_at": _now_iso(), "image_url": str(url),
            }
            self._save()
            return True

    def delivery(self, slot):
        with self.lock:
            self._prune()
            return self.state["deliveries"].get(slot)

    def image_path(self, slot):
        p = self.img_dir / (slot + ".jpg")
        return p if p.exists() else None


class RelayHandler(BaseHTTPRequestHandler):
    store = None  # set by make_server
    secret = ""

    def log_message(self, *a):  # keep stdout quiet; log one line per request
        sys.stderr.write("[relay] %s %s %s\n" % (self.client_address[0], self.command, self.path))

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _effective_secret(self):
        """v47: the bot auto-registered secret wins over the env/file
        secret (self.secret). Returns '' when neither is set."""
        try:
            reg = self.store.registered_secret() if self.store else ""
        except Exception:
            reg = ""
        if reg:
            return reg
        return (self.secret or "").strip()

    def _auth_ok(self):
        """v4 (hosted): accept EITHER the bot-registered secret OR the
        env/file secret. On a self-hosted VM Muse reads the registered
        secret from relay_state.json, but on a PaaS (Render) she cannot
        read the host filesystem — so the env secret (set by Muse at
        deploy time, known only to her) must also work. Both secrets are
        random and known only to an authorised party; accepting either
        does not weaken the other."""
        got = (self.headers.get("X-Relay-Secret") or "").strip()
        if not got:
            return False
        try:
            reg = self.store.registered_secret() if self.store else ""
        except Exception:
            reg = ""
        if reg and got == reg:
            return True
        env = (self.secret or "").strip()
        if env and got == env:
            return True
        return False

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            n = 0
        raw = self.rfile.read(n) if n > 0 else b""
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return None

    def do_GET(self):
        try:
            self._get()
        except Exception as e:
            self._json(500, {"ok": False, "error": "server error: %s" % str(e)[:200]})

    def do_POST(self):
        try:
            self._post()
        except Exception as e:
            self._json(500, {"ok": False, "error": "server error: %s" % str(e)[:200]})

    def _get(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/relay/health"):
            # v47: report whether a bot secret is registered (never the value).
            try:
                reg = bool(self.store.registered_secret()) if self.store else False
            except Exception:
                reg = False
            self._json(200, {"ok": True, "relay": "meownews24", "version": VERSION,
                             "bot_secret_registered": reg})
            return
        if not self._auth_ok():
            self._json(401, {"ok": False, "error": "unauthorized"})
            return
        if path == "/relay/pending":
            self._json(200, {"ok": True, "pending": self.store.pending()})
            return
        if path == "/relay/command":
            # v45: the bot polls for ONE pending Muse command. Claimed on
            # return (never returned twice); null when nothing is pending.
            cmd = self.store.claim_command()
            self._json(200, {"ok": True, "command": cmd})
            return
        if path == "/relay/command_result":
            # v45: Muse reads one outcome (?id=<cmd id>) or the latest.
            from urllib.parse import parse_qs, urlsplit
            _q = parse_qs(urlsplit(self.path).query)
            _cid = (_q.get("id") or [""])[0]
            res = self.store.command_result(_cid)
            self._json(200, {"ok": True, "result": res})
            return
        m = re.match(r"^/relay/delivered/([A-Za-z0-9_-]+)$", path)
        if m:
            slot = m.group(1)
            d = self.store.delivery(slot)
            if not d:
                self._json(200, {"ok": True, "delivered": False, "slot": slot})
                return
            image_url = d.get("image_url") or ("/relay/image/%s" % slot if d.get("stored") else "")
            self._json(200, {"ok": True, "delivered": True, "slot": slot,
                             "image_url": image_url,
                             "delivered_at": d.get("delivered_at") or ""})
            return
        m = re.match(r"^/relay/image/([A-Za-z0-9_-]+)$", path)
        if m:
            slot = m.group(1)
            d = self.store.delivery(slot)
            p = self.store.image_path(slot) if d and d.get("stored") else None
            if p is None:
                self._json(404, {"ok": False, "error": "no image for slot"})
                return
            data = p.read_bytes()
            ctype = d.get("content_type") or "image/jpeg"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._json(404, {"ok": False, "error": "unknown path"})

    def _post(self):
        path = self.path.split("?", 1)[0]
        if path == "/relay/register":
            # v47: bot auto-registers its own secret. NO auth by design —
            # the bot is the only one that knows the secret, and the user
            # never has to find/send it. Overwrites any stored secret.
            # The secret value is never logged or echoed.
            body = self._read_json()
            if body is None:
                self._json(400, {"ok": False, "error": "bad json"})
                return
            sec = str(body.get("secret") or "").strip()
            if not sec:
                self._json(400, {"ok": False, "error": "secret required"})
                return
            self.store.register_secret(sec)
            sys.stderr.write("[relay] bot secret registered\n")
            self._json(200, {"ok": True})
            return
        if not self._auth_ok():
            self._json(401, {"ok": False, "error": "unauthorized"})
            return
        if path == "/relay/request":
            body = self._read_json()
            if body is None:
                self._json(400, {"ok": False, "error": "bad json"})
                return
            if not str(body.get("slot") or ""):
                self._json(400, {"ok": False, "error": "slot required"})
                return
            if not self.store.add_request(body):
                self._json(400, {"ok": False, "error": "bad slot"})
                return
            self._json(200, {"ok": True, "slot": str(body.get("slot"))})
            return
        if path == "/relay/command":
            # v45: Muse posts ONE command. It becomes the pending command
            # (an older unclaimed one is superseded). Returns its id.
            body = self._read_json()
            if body is None:
                self._json(400, {"ok": False, "error": "bad json"})
                return
            cid = self.store.add_command(body)
            if not cid:
                self._json(400, {"ok": False, "error": "bad command (kind must be menu/series/numbered/review with its required fields)"})
                return
            self._json(200, {"ok": True, "id": cid})
            return
        if path == "/relay/command_result":
            # v45: the bot reports one command's outcome. Muse reads it
            # back via GET /relay/command_result?id=<id>.
            body = self._read_json()
            if body is None:
                self._json(400, {"ok": False, "error": "bad json"})
                return
            if not self.store.add_command_result(body):
                self._json(400, {"ok": False, "error": "id required"})
                return
            self._json(200, {"ok": True})
            return
        if path == "/relay/deliver":
            body = self._read_json()
            if body is None:
                self._json(400, {"ok": False, "error": "bad json"})
                return
            slot = str(body.get("slot") or "")
            if not slot:
                self._json(400, {"ok": False, "error": "slot required"})
                return
            if body.get("image_b64"):
                try:
                    data = base64.b64decode(str(body["image_b64"]), validate=True)
                except Exception:
                    self._json(400, {"ok": False, "error": "bad base64"})
                    return
                ctype = _sniff_image(data)
                if ctype is None:
                    self._json(400, {"ok": False, "error": "not an image"})
                    return
                if len(data) > 5 * 1024 * 1024:
                    self._json(400, {"ok": False, "error": "image too large (5MB max)"})
                    return
                if not self.store.deliver_bytes(slot, data, ctype):
                    self._json(400, {"ok": False, "error": "bad slot"})
                    return
                self._json(200, {"ok": True, "slot": slot, "stored": True})
                return
            if body.get("image_url"):
                if not self.store.deliver_url(slot, str(body["image_url"])):
                    self._json(400, {"ok": False, "error": "bad slot or url"})
                    return
                self._json(200, {"ok": True, "slot": slot, "stored": False})
                return
            self._json(400, {"ok": False, "error": "image_b64 or image_url required"})
            return
        self._json(404, {"ok": False, "error": "unknown path"})


def make_server(host, port, data_dir, secret):
    handler = type("Handler", (RelayHandler,), {})
    handler.store = RelayStore(data_dir)
    handler.secret = secret
    return ThreadingHTTPServer((host, port), handler)


def main():
    ap = argparse.ArgumentParser(description="MeowNews24 relay server (v36 images + v45 HTTP commands + v47 secret auto-registration)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--data-dir", default="")
    ap.add_argument("--secret", default="")
    ap.add_argument("--secret-file", default="")
    args = ap.parse_args()
    data_dir = args.data_dir or os.environ.get("RELAY_DATA_DIR") or str(
        Path.home() / "workspace" / "meownews24-relay" / "data")
    secret = (args.secret or os.environ.get("RELAY_SECRET") or "").strip()
    if args.secret_file:
        try:
            secret = Path(args.secret_file).read_text(encoding="utf-8").strip() or secret
        except Exception as e:
            print("relay: cannot read secret file: %s" % e, file=sys.stderr)
    # v47: a previously-registered bot secret (auto-registration) also
    # counts — the server may start without RELAY_SECRET when the bot has
    # already registered. If neither exists, refuse (same as v2).
    reg = ""
    try:
        _sf = Path(data_dir) / "relay_state.json"
        if _sf.exists():
            _raw = json.loads(_sf.read_text(encoding="utf-8"))
            reg = str((_raw or {}).get("bot_secret") or "").strip()
    except Exception:
        reg = ""
    if not secret and not reg:
        print("relay: RELAY_SECRET (or --secret / --secret-file) is required — "
              "it must match the bot's relay secret (or start once with it, "
              "so the bot can auto-register on /relay/register).", file=sys.stderr)
        return 2
    srv = make_server(args.host, args.port, data_dir, secret)
    print("relay: listening on %s:%d (data: %s)" % (args.host, args.port, data_dir), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
