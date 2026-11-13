#!/usr/bin/env python3
"""Test the hosted relay server v4 (deploy/render/relay_server.py).

Verifies the v4 auth fix: after the bot registers its secret, BOTH the
registered secret AND the env secret are accepted for authenticated
endpoints. Uses throwaway test secrets only; nothing real.
Run:  python3 test_relay_server_v4.py
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "relay_server.py")
PORT = 18765
BASE = "http://127.0.0.1:%d" % PORT
DATA_DIR = "/tmp/relay_v4_test_data"
ENV_SECRET = "test-env-secret-4a7b9c"
REG_SECRET = "test-registered-secret-1f2e3d"
WRONG_SECRET = "wrong-secret-zzzz"

passed = []
failed = []


def check(name, cond, detail=""):
    if cond:
        passed.append(name)
        print("PASS %s" % name)
    else:
        failed.append(name)
        print("FAIL %s  %s" % (name, detail))


def req(method, path, secret=None, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if secret is not None:
        r.add_header("X-Relay-Secret", secret)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def main():
    import shutil
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    env = dict(os.environ)
    env["RELAY_SECRET"] = ENV_SECRET
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--host", "127.0.0.1", "--port", str(PORT),
         "--data-dir", DATA_DIR],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        # Wait for the server to come up.
        ok = False
        for _ in range(30):
            try:
                s, b = req("GET", "/relay/health")
                if s == 200:
                    ok = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
        check("t1 server starts and health answers", ok)
        if not ok:
            print(proc.stdout.read() if proc.stdout else "")
            return 1
        s, b = req("GET", "/relay/health")
        check("t2 health version is 4", b.get("version") == 4, str(b))
        check("t3 health bot_secret_registered false before register",
              b.get("bot_secret_registered") is False, str(b))

        # Before registration, the env secret authenticates.
        s, b = req("POST", "/relay/command", secret=ENV_SECRET,
                   body={"kind": "menu", "number": 10})
        check("t4 command POST with env secret works before register",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
        s, b = req("GET", "/relay/command", secret=ENV_SECRET)
        check("t5 command GET (bot poll) with env secret returns the command",
              s == 200 and (b.get("command") or {}).get("kind") == "menu",
              "%s %s" % (s, b))

        # Register the bot's secret (no auth on /relay/register).
        s, b = req("POST", "/relay/register", body={"secret": REG_SECRET})
        check("t6 register returns ok:true", s == 200 and b.get("ok") is True,
              "%s %s" % (s, b))
        s, b = req("GET", "/relay/health")
        check("t7 health bot_secret_registered true after register",
              b.get("bot_secret_registered") is True, str(b))

        # v4 fix: AFTER registration, the ENV secret must STILL work.
        s, b = req("POST", "/relay/command", secret=ENV_SECRET,
                   body={"kind": "menu", "number": 12})
        check("t8 command POST with ENV secret still works AFTER register (v4 fix)",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
        # And the REGISTERED secret works too.
        s, b = req("POST", "/relay/command", secret=REG_SECRET,
                   body={"kind": "series", "text": "test series part"})
        check("t9 command POST with REGISTERED secret works after register",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
        # A wrong secret is rejected.
        s, b = req("POST", "/relay/command", secret=WRONG_SECRET,
                   body={"kind": "menu", "number": 10})
        check("t10 wrong secret gets 401", s == 401, "%s %s" % (s, b))
        # No secret is rejected.
        s, b = req("POST", "/relay/command",
                   body={"kind": "menu", "number": 10})
        check("t11 missing secret gets 401", s == 401, "%s %s" % (s, b))
        # Bot polls the latest command with the registered secret.
        s, b = req("GET", "/relay/command", secret=REG_SECRET)
        check("t12 bot poll with registered secret returns latest command",
              s == 200 and (b.get("command") or {}).get("kind") == "series",
              "%s %s" % (s, b))
        # Bot reports a result; Muse reads it with the env secret.
        cmd = (b.get("command") or {})
        cid = cmd.get("id") or ""
        s, b = req("POST", "/relay/command_result", secret=REG_SECRET,
                   body={"id": cid, "ok": True, "detail": "done"})
        check("t13 command_result POST with registered secret works",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
        s, b = req("GET", "/relay/command_result", secret=ENV_SECRET)
        check("t14 command_result GET with env secret returns the result",
              s == 200 and (b.get("result") or {}).get("ok") is True,
              "%s %s" % (s, b))
        # Registering a different secret overwrites (bot re-register).
        s, b = req("POST", "/relay/register", body={"secret": "test-reg-2"})
        check("t15 re-register overwrites and returns ok",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
        s, b = req("POST", "/relay/command", secret="test-reg-2",
                   body={"kind": "menu", "number": 10})
        check("t16 new registered secret works, old one does not (after overwrite)",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
        s, b = req("POST", "/relay/command", secret=REG_SECRET,
                   body={"kind": "menu", "number": 10})
        check("t17 old registered secret rejected after overwrite",
              s == 401, "%s %s" % (s, b))
        # Env secret still works after re-register (v4 fix, persistent).
        s, b = req("POST", "/relay/command", secret=ENV_SECRET,
                   body={"kind": "menu", "number": 10})
        check("t18 env secret still works after re-register",
              s == 200 and b.get("ok") is True, "%s %s" % (s, b))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        import shutil
        shutil.rmtree(DATA_DIR, ignore_errors=True)

    print("\n%d/%d passed" % (len(passed), len(passed) + len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
