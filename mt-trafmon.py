#!/usr/bin/env python3
"""
mt-trafmon — MikroTik traffic monitor
======================================
Version : 0.1.0
License : MIT

Single-file tool that:
  • Collects per-second RX/TX from a MikroTik router via the RouterOS API
  • Stores measurements in a local RRD database (~835 MB, pre-allocated)
  • Serves a self-contained dark-themed web UI with interactive graphs

No external web server, database engine, or JavaScript framework required.
Runs as a single Python process with an embedded ThreadingHTTPServer.

RRD retention schedule
-----------------------
  1 second   — 1 year   (raw samples)
  10 seconds — 5 years  (averaged)
  1 minute   — 5 years  (avg + max)
  5 minutes  — 10 years (avg + max)

Setup
-----
  python3 mt-trafmon.py

  Runs automatically when no config is found, or with -s / --setup.
  All settings are saved to mt-trafmon.ini next to this script.

Command-line flags
------------------
  -q / --quiet     Suppress per-sample log output (recommended with systemd)
  -s / --setup     Force the interactive setup wizard
  -v / --version   Print the script modification date and exit
  -w / --web-only  Run web server only — serve graphs from an existing RRD
                   file without connecting to the router or collecting data

Config: [router]
-----------------
  host           = 192.168.88.1
  user           = admin
  password       =                (machine-encrypted, written by the script)
  password_plain =                (plain-text override; removed on next save)
  interface      = ether1

Config: [storage]
------------------
  rrd_file = traffic.rrd

Config: [web]
-------------
  enabled    = true
  port       = 8080
  page_title = MikroTik Traffic Monitor
  allow      = 127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  dark_graph = true

Password storage
----------------
  Passwords are XOR-obfuscated with a key derived from /etc/machine-id,
  making the stored value host-specific.  To move to a new machine, set
  password_plain = yourpassword in the ini; the script re-encrypts on next
  save and removes the plain-text entry.

Changelog
---------
  0.1.0  Initial release
"""

import argparse
import base64
import configparser
import copy
import getpass
import hashlib
import html
import ipaddress
import json
import logging
import os
import pathlib
import secrets
import signal
import socket
import sys
import tempfile
import threading
import time
import urllib.parse
import concurrent.futures
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer


# ---------------------------------------------------------------------------
# Non-stdlib imports
# ---------------------------------------------------------------------------
try:
    from librouteros import connect as ros_connect
    from librouteros.exceptions import LibRouterosError
except ImportError:
    sys.exit(
        "ERROR: librouteros is not installed.\n"
        "  pip install librouteros\n"
        "  sudo pip install --break-system-packages librouteros\n"
    )

try:
    import rrdtool
except ImportError:
    sys.exit(
        "ERROR: rrdtool Python binding is not installed.\n"
        "  sudo apt install python3-rrdtool   (Debian/Ubuntu recommended)\n"
        "  pip install rrdtool\n"
    )


# ---------------------------------------------------------------------------
# Paths & defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR  = pathlib.Path(__file__).resolve().parent
CONFIG_FILE = SCRIPT_DIR / "mt-trafmon.ini"

DEFAULT_ALLOW = "127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"

DEFAULTS = {
    "router": {
        "host":           "192.168.88.1",
        "user":           "admin",
        "password":       "",
        "password_plain": "",   # plain-text override; takes priority over encrypted password
        "interface":      "ether1",
    },
    "storage": {
        "rrd_file": str(SCRIPT_DIR / "traffic.rrd"),
    },
    "web": {
        "enabled":    "true",
        "port":       "8080",
        "page_title": "MikroTik Traffic Monitor",
        "allow":      DEFAULT_ALLOW,
        "dark_graph": "true",
    },
}


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
class State:
    cfg        = None               # ConfigParser — always set before use
    setup_done = threading.Event()  # set when config is saved by either path
    last_rx    = 0
    last_tx    = 0
    last_ts    = None               # None until first sample received
    lock       = threading.Lock()

    # Web-server control — written only from the main thread or under _srv_lock
    _srv_lock    = threading.Lock()
    _server      = None             # current HTTPServer instance
    _restart_port = None            # set to new port number to trigger restart
    _shutdown_flag = False          # set to True for a real shutdown (no restart)

    # ACL cache — rebuilt only when cfg changes
    _acl_cache   = None
    _acl_cfg_ver = 0                # bumped whenever STATE.cfg is replaced

    # Config watcher / collector reconnect signal
    reconnect_event = threading.Event()   # set to force collector reconnect

    # CSRF token generated once at startup, validated on every POST /setup (V1)
    csrf_token = secrets.token_hex(32)

STATE = State()


def request_server_restart(new_port: int) -> None:
    """
    Called from any thread when the port has changed after saving config.
    Signals the main serve-loop to restart on new_port.
    """
    with STATE._srv_lock:
        if STATE._server is None:
            return
        STATE._restart_port = new_port
        STATE._server.shutdown()        # unblocks serve_forever() on main thread


def request_server_shutdown() -> None:
    """Clean shutdown — no restart."""
    STATE._shutdown_flag = True
    with STATE._srv_lock:
        if STATE._server is None:
            return
        STATE._server.shutdown()


# ---------------------------------------------------------------------------
# Password obfuscation
# ---------------------------------------------------------------------------

def _machine_key() -> bytes:
    raw = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            raw = pathlib.Path(path).read_text().strip()
            break
        except OSError:
            pass
    if not raw:
        raw = "mt-trafmon-static-fallback-key-v1"
    return hashlib.sha256(raw.encode()).digest()


_KEY = _machine_key()


def encrypt_password(plaintext: str) -> str:
    if not plaintext:
        return ""
    data = plaintext.encode("utf-8")
    enc  = bytes(data[i] ^ _KEY[i % len(_KEY)] for i in range(len(data)))
    return "xor:" + base64.b64encode(enc).decode()


def decrypt_password(stored: str) -> str:
    if not stored or not stored.startswith("xor:"):
        return stored
    try:
        enc  = base64.b64decode(stored[4:])
        data = bytes(enc[i] ^ _KEY[i % len(_KEY)] for i in range(len(enc)))
        return data.decode("utf-8")
    except Exception:
        return stored


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def validate_port(value: str, fallback: int = 8080) -> int:
    """Parse port string, clamp to valid range, return int."""
    try:
        p = int(value)
    except (ValueError, TypeError):
        p = fallback
    if not 1 <= p <= 65535:
        logging.warning("Port %s out of range — using %d", value, fallback)
        return fallback
    return p


def default_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    for section, values in DEFAULTS.items():
        cfg[section] = dict(values)
    return cfg


def load_config() -> configparser.ConfigParser:
    cfg = default_cfg()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)
    return cfg


def save_config(cfg: configparser.ConfigParser) -> None:
    """Write config to disk.
    The password is ALWAYS saved in encrypted form.
    password_plain is ALWAYS removed from the saved file.
    The caller must put the active plain-text password in cfg["router"]["password"]
    before calling save_config (as a plain string — we encrypt it here).
    """
    out = copy.deepcopy(cfg)
    # Determine the active plain-text password (plain takes priority)
    plain = out.get("router", "password_plain", fallback="").strip()             or decrypt_password(out.get("router", "password", fallback=""))
    # Always save encrypted, always remove password_plain
    out["router"]["password"]       = encrypt_password(plain) if plain else ""
    out["router"]["password_plain"] = ""
    with open(CONFIG_FILE, "w") as f:
        out.write(f)
    logging.info("Config saved to %s", CONFIG_FILE)


def get_password(cfg: configparser.ConfigParser) -> str:
    """Return the plain-text router password (plain takes priority over encrypted)."""
    plain_override = cfg.get("router", "password_plain", fallback="").strip()
    if plain_override:
        return plain_override
    return decrypt_password(cfg.get("router", "password", fallback=""))


def resolve_password(cfg: configparser.ConfigParser,
                     host: str, user: str, interface: str) -> tuple:
    """Try password_plain first, then encrypted password.
    Returns (plain_text_password, validated_ok, message).
    If password_plain is present and validates, that is the active password.
    If password_plain fails or is absent, try the encrypted password.
    Either way the caller gets back a plain-text string to use/save.
    """
    plain  = cfg.get("router", "password_plain", fallback="").strip()
    enc_pw = decrypt_password(cfg.get("router", "password", fallback=""))

    if plain:
        ok, msg = test_router(host, user, plain, interface)
        if ok:
            return plain, True, msg
        # plain failed — try encrypted fallback if available
        if enc_pw:
            ok2, msg2 = test_router(host, user, enc_pw, interface)
            if ok2:
                logging.warning("password_plain failed (%s); using encrypted password instead", msg)
                return enc_pw, True, msg2
        # both failed — return plain (the user-supplied one) with the error
        return plain, False, msg

    if enc_pw:
        ok, msg = test_router(host, user, enc_pw, interface)
        return enc_pw, ok, msg

    return "", False, "No password configured"


def config_is_complete(cfg: configparser.ConfigParser) -> bool:
    return bool(get_password(cfg).strip())


def apply_fields(cfg: configparser.ConfigParser, fields: dict) -> None:
    cfg["router"]["host"]           = fields.get("host",           cfg["router"]["host"]).strip()
    cfg["router"]["user"]           = fields.get("user",           cfg["router"]["user"]).strip()
    pw = fields.get("password", "").strip()
    if pw:
        cfg["router"]["password"]   = pw
    # password_plain: explicit empty string means "clear it"; absence means "leave as-is"
    if "password_plain" in fields:
        cfg["router"]["password_plain"] = fields["password_plain"].strip()
    cfg["router"]["interface"]      = fields.get("interface",      cfg["router"]["interface"]).strip()
    cfg["storage"]["rrd_file"]  = fields.get("rrd_file",    cfg["storage"]["rrd_file"]).strip()
    raw_en = fields.get("web_enabled", cfg["web"]["enabled"]).strip().lower()
    cfg["web"]["enabled"] = "false" if raw_en in ("false","0","no") else "true"
    cfg["web"]["port"]          = fields.get("port",        cfg["web"]["port"]).strip()
    cfg["web"]["page_title"]    = fields.get("page_title",  cfg["web"]["page_title"]).strip()
    cfg["web"]["allow"]         = fields.get("allow",       cfg["web"]["allow"]).strip()
    if "dark_graph" in fields:
        cfg["web"]["dark_graph"]    = fields["dark_graph"].strip()


# ---------------------------------------------------------------------------
# IP access control
# ---------------------------------------------------------------------------

def parse_acl(acl_string: str) -> list:
    items = []
    for entry in acl_string.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "/" in entry:
            try:
                items.append(("network", ipaddress.ip_network(entry, strict=False)))
            except ValueError:
                logging.warning("ACL: ignoring bad CIDR entry: %r", entry)
        else:
            try:
                items.append(("host", ipaddress.ip_address(entry)))
            except ValueError:
                items.append(("hostname", entry))
    return items


def is_allowed(client_ip: str, acl_items: list) -> bool:
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.1 -> 192.168.1.1)
    # so that IPv4 ACL entries match connections on dual-stack sockets.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for kind, val in acl_items:
        if kind == "network" and addr in val:
            return True
        if kind == "host" and addr == val:
            return True
        if kind == "hostname":
            try:
                for info in socket.getaddrinfo(val, None):
                    try:
                        resolved = ipaddress.ip_address(info[4][0])
                        if isinstance(resolved, ipaddress.IPv6Address) and resolved.ipv4_mapped:
                            resolved = resolved.ipv4_mapped
                        if resolved == addr:
                            return True
                    except ValueError:
                        pass
            except socket.gaierror:
                pass
    return False


# ---------------------------------------------------------------------------
# RRD helpers
# ---------------------------------------------------------------------------

def init_rrd(rrd_file: str) -> None:
    if os.path.exists(rrd_file):
        return
    d = os.path.dirname(rrd_file)
    if d:
        os.makedirs(d, exist_ok=True)
    rrdtool.create(
        rrd_file,
        "--start", "now-2", "--step", "1",
        "DS:rx:GAUGE:3:0:U",
        "DS:tx:GAUGE:3:0:U",
        "RRA:AVERAGE:0.5:1:31557600",
        "RRA:AVERAGE:0.5:10:15778800",
        "RRA:AVERAGE:0.5:60:2629800",
        "RRA:MAX:0.5:60:2629800",
        "RRA:AVERAGE:0.5:300:1051920",
        "RRA:MAX:0.5:300:1051920",
    )
    logging.info("Created RRD file: %s", rrd_file)


def rrd_checks(rrd_file: str) -> list:
    problems = []
    d = os.path.dirname(rrd_file) or "."
    if not os.path.isdir(d):
        problems.append(f"Directory does not exist: {d}")
    elif not os.access(d, os.R_OK):
        problems.append(f"Directory is not readable: {d}")
    if not problems:
        if not os.path.exists(rrd_file):
            problems.append(f"RRD file does not exist yet: {rrd_file} (collector may not have started)")
        elif not os.access(rrd_file, os.R_OK):
            problems.append(f"RRD file is not readable: {rrd_file}")
    return problems


def fetch_totals(rrd_file: str, start: int, end: int) -> dict:
    try:
        span = max(1, end - start)
        step = 1 if span <= 31557600 else (10 if span <= 157788000 else 300)
        result = rrdtool.fetch(rrd_file, "AVERAGE",
                               "--start", str(start), "--end", str(end),
                               "--resolution", str(step))
        (_, _, fetch_step), ds_names, rows = result
        ri, ti = ds_names.index("rx"), ds_names.index("tx")
        rx_b = sum((r[ri] or 0) * fetch_step for r in rows) / 8
        tx_b = sum((r[ti] or 0) * fetch_step for r in rows) / 8
        return dict(rx_bytes=rx_b, tx_bytes=tx_b,
                    rx_human=human_bytes(rx_b), tx_human=human_bytes(tx_b))
    except Exception as e:
        logging.warning("fetch_totals failed: %s", e)
        return dict(rx_bytes=0, tx_bytes=0, rx_human="—", tx_human="—")


# ---------------------------------------------------------------------------
# Router test
# ---------------------------------------------------------------------------

def test_router(host: str, user: str, password: str, interface: str) -> tuple:
    try:
        api    = ros_connect(host=host, username=user, password=password, timeout=5)
        ifaces = [r.get("name", "") for r in api.path("interface")]
        api.close()
        if interface not in ifaces:
            return False, (f"Connected OK, but interface '{interface}' not found. "
                           f"Available: {', '.join(ifaces)}")
        return True, f"Connected. Interface '{interface}' found."
    except LibRouterosError as e:
        return False, f"RouterOS error: {e}"
    except OSError as e:
        return False, f"Network error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


# ---------------------------------------------------------------------------
# TTY setup  (runs in its own thread — parallel with web setup)
# ---------------------------------------------------------------------------

def tty_setup(cfg: configparser.ConfigParser) -> configparser.ConfigParser:
    """Blocking interactive terminal setup wizard. Returns the saved config."""
    print()
    print("=" * 60)
    print("  mt-trafmon — setup")
    print("=" * 60)
    print()

    def ask(prompt: str, default: str, secret: bool = False) -> str:
        disp = f" [{default}]" if default else ""
        val  = (getpass.getpass if secret else input)(f"  {prompt}{disp}: ").strip()
        return val if val else default

    local = copy.deepcopy(cfg)
    local["router"]["host"]      = ask("Router IP address",  local["router"]["host"])
    local["router"]["user"]      = ask("RouterOS username",  local["router"]["user"])
    # Password prompt — mandatory on first run, optional (blank = keep) when one exists
    existing_pw = get_password(cfg)
    if existing_pw:
        print("  (a password is already stored; press Enter to keep it)")
        new_pw = ask("RouterOS password (blank = keep current)", "", secret=True)
        local["router"]["password"] = new_pw if new_pw else existing_pw
    else:
        while True:
            new_pw = ask("RouterOS password", "", secret=True)
            if new_pw:
                local["router"]["password"] = new_pw
                break
            print("  Password is required — please enter it.")
    local["router"]["password_plain"] = ""   # TTY setup never keeps plain text
    local["router"]["interface"] = ask("WAN interface name", local["router"]["interface"])
    local["storage"]["rrd_file"] = ask("RRD data file path", local["storage"]["rrd_file"])
    we = ask("Enable web server? [Y/n]", "y").lower()
    local["web"]["enabled"]      = "false" if we.startswith("n") else "true"
    local["web"]["port"]         = ask("Web server port",    local["web"]["port"])
    local["web"]["page_title"]   = ask("Page title",         local["web"]["page_title"])
    local["web"]["allow"]        = ask("Allowed IPs/networks (comma-separated)",
                                       local["web"]["allow"])

    if STATE.setup_done.is_set():
        print("\n  [Web setup completed first — TTY entries discarded]")
        return

    print()
    print("  Testing router connection…", end=" ", flush=True)
    ok, msg = test_router(local["router"]["host"], local["router"]["user"],
                          local["router"]["password"],   # already plain text
                          local["router"]["interface"])
    print("OK" if ok else "FAILED")
    print(f"  {msg}")
    print()

    if not ok:
        if STATE.setup_done.is_set():
            print("  [Web setup completed while testing — TTY entries discarded]")
            return
        retry = input("  Save anyway and continue? [y/N]: ").strip().lower()
        if retry != "y":
            print("  TTY setup cancelled.")
            # Don't exit the process — web setup may still be in progress
            return

    STATE.cfg = local
    save_config(local)
    print("  Setup complete.")
    return local


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def h(s) -> str:
    return html.escape(str(s), quote=True)


def human_duration(seconds: int) -> str:
    if seconds < 60:    return f"{seconds} second{'s' if seconds != 1 else ''}"
    if seconds < 3600:  return f"{round(seconds/60,  1)} minutes"
    if seconds < 86400: return f"{round(seconds/3600, 1)} hours"
    return f"{round(seconds/86400, 1)} days"


def human_bytes(b: float) -> str:
    if b < 0: return "—"
    for unit in ("B","KB","MB","GB","TB"):
        if b < 1024: return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"


def range_to_seconds(r: str) -> int:
    return {"5m":300,"15m":900,"1h":3600,"6h":21600,"24h":86400,
            "7d":604800,"30d":2592000,"1y":31557600,"5y":157788000}.get(r, 3600)


def resolution_for_window(start: int, end: int, width: int) -> dict:
    span = max(1, end - start)
    if   span <= 31557600:  archive_step, archive_label = 1,   "1 second RRD archive"
    elif span <= 157788000: archive_step, archive_label = 10,  "10 second RRD archive"
    else:                   archive_step, archive_label = 300, "5 minute RRD archive"
    pixel_step     = max(1, -(-span // max(1, width)))
    effective_step = max(archive_step, pixel_step)
    return dict(effective_step=effective_step,
                effective_label=human_duration(effective_step),
                archive_step=archive_step, archive_label=archive_label,
                pixel_step=pixel_step, pixel_label=human_duration(pixel_step))


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

SHARED_CSS = """
:root{color-scheme:dark;--bg:#0f1117;--panel:#171b24;--panel2:#202635;
    --panel3:#111621;--text:#f2f5fa;--muted:#9aa6b8;--border:#303848;}
*{box-sizing:border-box;}
body{margin:0;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    background:radial-gradient(circle at top left,rgba(87,166,255,.12),transparent 35%),var(--bg);
    color:var(--text);}
header{padding:22px 28px;border-bottom:1px solid var(--border);background:rgba(15,17,23,.88);}
h1{margin:0 0 6px;font-size:22px;}
.sub{color:var(--muted);font-size:13px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;}
main{padding:22px;max-width:1800px;}
.panel{background:rgba(23,27,36,.96);border:1px solid var(--border);border-radius:16px;
    padding:18px;margin-bottom:18px;box-shadow:0 10px 35px rgba(0,0,0,.22);}
label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px;}
select,input,button{width:100%;background:var(--panel2);color:var(--text);
    border:1px solid var(--border);border-radius:10px;padding:10px;font-size:14px;}
button{cursor:pointer;background:linear-gradient(180deg,#2c5d91,#224871);border-color:#3d74ad;}
button:hover{filter:brightness(1.1);}
button.secondary{background:var(--panel2);}
button.danger{background:#5c2730;border-color:#8d3d4b;}
.controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;align-items:end;}
.wide{grid-column:1/-1;}
.checks{display:flex;gap:16px;align-items:center;min-height:39px;}
.checks label{display:flex;gap:8px;align-items:center;margin:0;color:var(--text);}
.checks input{width:auto;}
.quick{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;}
.quick button{width:auto;padding:8px 12px;}
.graph-panel{padding:14px;}
.graph-toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;
    margin-bottom:10px;color:var(--muted);font-size:13px;flex-wrap:wrap;}
.graph-frame{overflow:auto;padding:8px;background:var(--panel3);
    border:1px solid var(--border);border-radius:14px;text-align:center;}
.graph-holder{position:relative;display:inline-block;line-height:0;}
#graph{display:block;max-width:none;background:#fff;border-radius:8px;cursor:crosshair;user-select:none;}
#selection{position:absolute;top:0;bottom:0;background:rgba(87,166,255,.22);
    border-left:2px solid rgba(87,166,255,.95);border-right:2px solid rgba(87,166,255,.95);
    display:none;pointer-events:none;}
.footer{color:var(--muted);font-size:12px;}
.smallgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;
    background:#20334e;color:#b9d9ff;border:1px solid #31557f;}
.badge.resolution{background:#243f2f;color:#bff3d1;border-color:#3a7a51;}
.badge.warning{background:#4a3520;color:#ffd9a6;border-color:#8a6630;}
.note{color:var(--muted);font-size:12px;margin-top:10px;}
.panel.error-panel{border-color:#7a3040;background:rgba(60,20,28,.95);}
.error-panel h2{margin:0 0 14px;font-size:16px;color:#ffb3be;}
.error-panel ul{margin:0;padding:0 0 0 18px;color:#ffd0d6;font-size:14px;line-height:1.9;}
.error-panel code{font-family:monospace;background:rgba(0,0,0,.3);padding:1px 5px;border-radius:4px;}
.error-panel .hint{margin-top:14px;font-size:12px;color:#c0828e;}
.msg.ok{color:#a8f0c0;padding:10px;background:rgba(0,80,40,.4);border-radius:8px;margin-bottom:14px;}
.msg.fail{color:#ffb3be;padding:10px;background:rgba(80,0,20,.4);border-radius:8px;margin-bottom:14px;}
.live{color:var(--muted);font-size:13px;}
.live span{color:var(--text);font-weight:600;}
.restart-banner{background:#2a3f1e;border:1px solid #4a7a30;border-radius:10px;
    padding:12px 16px;margin-bottom:14px;color:#c8f0a0;font-size:13px;}
"""


def page_shell(title: str, body: str, extra_js: str = "") -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<title>{h(title)}</title>'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<style>{SHARED_CSS}</style></head><body>{body}'
            + (f'<script>{extra_js}</script>' if extra_js else '')
            + '</body></html>')


# ---------------------------------------------------------------------------
# Setup page
# ---------------------------------------------------------------------------

def build_setup_page(cfg: configparser.ConfigParser,
                     message: str = "", msg_ok: bool = False,
                     redirect_port: int = 0) -> str:
    msg_html = ""
    if message:
        cls = "ok" if msg_ok else "fail"
        msg_html = f'<p class="msg {cls}">{h(message)}</p>'

    # If port changed, redirect browser to main page on new port after restart
    redirect_js = ""
    if redirect_port:
        redirect_js = (f'setTimeout(()=>'
                       f'{{window.location.href="http://"+window.location.hostname'
                       f'+":{redirect_port}/";}}, 3000);')
        msg_html += (f'<div class="restart-banner">⟳ Web server restarting on port '
                     f'<strong>{redirect_port}</strong> — '
                     f'redirecting to main page in 3 seconds…</div>')

    def v(sec, key):
        return h(cfg.get(sec, key, fallback=""))

    web_en = cfg.get("web","enabled",fallback="true").strip().lower() not in ("false","0","no")

    body = f"""
<header>
  <h1>mt-trafmon — Settings
    <a href="/" style="font-size:14px;font-weight:normal;margin-left:16px;color:var(--muted);text-decoration:none;border:1px solid var(--border);padding:4px 10px;border-radius:8px;vertical-align:middle">← Back to graph</a>
  </h1>
  <div class="sub">Router credentials and server options.</div>
</header>
<main>
  <div class="panel">
    <form method="POST" action="/setup">
      <input type="hidden" name="csrf_token" value="{h(STATE.csrf_token)}">
      {msg_html}
      <h2 style="margin-top:0">Router</h2>
      <div class="controls">
        <div><label>IP address</label>
          <input name="host"      value="{v('router','host')}"      placeholder="192.168.88.1"></div>
        <div><label>Username</label>
          <input name="user"      value="{v('router','user')}"      placeholder="admin"></div>
        <div><label>Password <small style="color:var(--muted)">(leave blank to keep current)</small></label>
          <input name="password_plain" type="password" autocomplete="new-password"
                 placeholder="enter password (stored as plain text in config)"></div>
        <div><label>WAN interface
            <small style="color:var(--muted)" id="ifaceStatus"></small></label>
          <select name="interface" id="ifaceSelect">
            <option value="{v('router','interface')}">{v('router','interface') or 'ether1'}</option>
          </select></div>
      </div>
      <h2>Storage</h2>
      <div class="controls">
        <div><label>RRD data file path</label>
          <input name="rrd_file" value="{v('storage','rrd_file')}"></div>
      </div>
      <h2>Web server</h2>
      <div class="controls">
        <div><label>Port</label>
          <input name="port"       value="{v('web','port')}"       placeholder="8080"></div>
        <div><label>Page title</label>
          <input name="page_title" value="{v('web','page_title')}"></div>
        <div><label>Status</label>
          <select name="web_enabled">
            <option value="true"  {"selected" if web_en else ""}>Enabled</option>
            <option value="false" {"selected" if not web_en else ""}>Disabled (collector only)</option>
          </select></div>
        <div><label>Graph background</label>
          <select name="dark_graph">
            {"<option value='true' selected>Dark</option><option value='false'>White (classic)</option>" if cfg.get("web","dark_graph",fallback="true").strip().lower() not in ("false","0","no") else "<option value='true'>Dark</option><option value='false' selected>White (classic)</option>"}
          </select></div>
        <div class="wide"><label>Allowed source IPs / networks / hostnames (comma-separated)</label>
          <input name="allow" value="{v('web','allow')}"></div>
      </div>
      <div style="margin-top:18px;display:flex;gap:12px;flex-wrap:wrap">
        <button type="submit" name="action" value="test"  style="max-width:200px">Test connection</button>
        <button type="submit" name="action" value="save"  style="max-width:200px">Save &amp; apply</button>
        <button type="button" onclick="loadInterfaces()" style="max-width:200px;background:var(--panel2)">↻ Load interfaces</button>
      </div>
    </form>
    <script>
    function loadInterfaces(){{
      const sel=document.getElementById('ifaceSelect');
      const st=document.getElementById('ifaceStatus');
      st.textContent=' loading…';
      fetch('/api/interfaces').then(r=>r.json()).then(d=>{{
        if(d.error){{ st.textContent=' ⚠ '+d.error; return; }}
        const cur=sel.value;
        sel.innerHTML='';
        d.interfaces.forEach(name=>{{
          const o=document.createElement('option');
          o.value=o.textContent=name;
          if(name===cur) o.selected=true;
          sel.appendChild(o);
        }});
        if(!sel.value && d.interfaces.length) sel.value=d.interfaces[0];
        st.textContent=' ✓ '+d.interfaces.length+' interfaces';
      }}).catch(e=>{{ st.textContent=' ⚠ '+e; }});
    }}
    // Auto-load when host/user/password fields blur
    ['host','user'].forEach(n=>{{
      const el=document.querySelector('[name='+n+']');
      if(el) el.addEventListener('blur', loadInterfaces);
    }});
    </script>
  </div>
</main>"""
    return page_shell("mt-trafmon settings", body, redirect_js)


# ---------------------------------------------------------------------------
# Main graph page
# ---------------------------------------------------------------------------

def build_graph_page(cfg: configparser.ConfigParser, params: dict) -> str:
    rrd_file = cfg.get("storage","rrd_file")
    title    = cfg.get("web",    "page_title")
    problems = rrd_checks(rrd_file)

    range_    = params.get("range","1h")
    width     = max(300,  min(4000, int(params.get("width",  1200))))
    height    = max(150,  min(2000, int(params.get("height", 420))))
    style     = params.get("style","area")
    if style not in ("area","line","mirror"): style = "area"
    log_scale   = params.get("log",    "0") == "1"
    smooth      = params.get("smooth", "0") == "1"
    show_volume = params.get("volume", "1") == "1"
    try:
        refresh_sec = int(params.get("refresh", "0") or "0")
        if refresh_sec not in (0, 5, 30, 60):
            refresh_sec = 0
    except (ValueError, TypeError):
        refresh_sec = 0

    try:
        graph_start = int(params["start"])
        graph_end   = int(params["end"])
        if graph_end <= graph_start: raise ValueError
        range_ = "custom"
    except (KeyError, ValueError):
        graph_end   = int(time.time())
        graph_start = graph_end - range_to_seconds(range_)

    res        = resolution_for_window(graph_start, graph_end, width)
    from_label = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(graph_start))
    to_label   = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(graph_end))
    span_secs  = graph_end - graph_start
    span_label = human_duration(span_secs)

    # query with cache-buster for the <img> tag (forces reload on redraw)
    # Page URL query — always bakes explicit start/end (preserves drag-zoom state)
    query = urllib.parse.urlencode({
        "graph":1,"start":graph_start,"end":graph_end,
        "width":width,"height":height,"style":style,
        "log":"1" if log_scale else "0",
        "smooth":"1" if smooth else "0",
        "volume":"1" if show_volume else "0",
        "refresh":str(refresh_sec),
        "_":int(time.time()),
    })
    # clean_query — no cache-buster, used for the Copy Link button
    clean_query = urllib.parse.urlencode({
        "graph":1,"start":graph_start,"end":graph_end,
        "width":width,"height":height,"style":style,
        "log":"1" if log_scale else "0",
        "smooth":"1" if smooth else "0",
        "volume":"1" if show_volume else "0",
        "refresh":str(refresh_sec),
    })
    # img_query — the <img> src.  For preset ranges (non-custom) we omit
    # start/end so each browser load (including auto-refresh) recomputes the
    # window from "now", keeping the graph live.  Custom zoom keeps fixed epochs.
    _common = {
        "graph":1,"width":width,"height":height,"style":style,
        "log":"1" if log_scale else "0",
        "smooth":"1" if smooth else "0",
        "volume":"1" if show_volume else "0",
        "_":int(time.time()),
    }
    if range_ == "custom":
        img_query = urllib.parse.urlencode({**_common,
                                            "start":graph_start,"end":graph_end})
    else:
        img_query = urllib.parse.urlencode({**_common, "range":range_})
    setup_link = '<a href="/setup" style="color:var(--muted);font-size:12px;margin-left:12px">⚙ settings</a>'

    header = f"""
<header>
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <h1 style="margin:0">{h(title)}{setup_link}</h1>
    <span class="live" id="liveStats" style="font-size:13px">Live stats loading…</span>
  </div>
</header>"""

    if problems:
        items = "".join(f"<li><code>{h(p)}</code></li>" for p in problems)
        return page_shell(title, header + f"""
<main><div class="panel error-panel">
  <h2>⚠ RRD data file problem</h2><ul>{items}</ul>
  <p class="hint">The collector must be running. Check
  <a href="/setup" style="color:#c0828e">settings</a> if the path looks wrong.</p>
</div></main>""")

    totals = fetch_totals(rrd_file, graph_start, graph_end) if show_volume else None

    ranges_html = "".join(
        f'<option value="{r}" {"selected" if range_==r else ""}>{r}</option>'
        for r in ["5m","15m","1h","6h","24h","7d","30d","1y","5y"]
    ) + f'<option value="custom" {"selected" if range_=="custom" else ""}>custom zoom</option>'

    # Build a rrdtool CLI command string for the current graph params.
    # This mirrors generate_graph() but produces shell-quoted CLI output.
    import shlex
    _rrd  = rrd_file
    _title = cfg.get("web", "page_title", fallback="mt-trafmon")
    _step  = res["effective_step"]
    _range_map = {"5m":"5min","15m":"15min","1h":"1h","6h":"6h",
                  "24h":"1d","7d":"1w","30d":"30d","1y":"1y","5y":"5y"}
    if range_ != "custom" and range_ in _range_map:
        _cli_start, _cli_end = f"now-{_range_map[range_]}", "now"
    else:
        _cli_start, _cli_end = str(graph_start), str(graph_end)
    _cli_args = [
        "rrdtool", "graph", "output.png",
        "--start", _cli_start, "--end", _cli_end,
        "--step",   str(_step),
        "--width",  str(width),  "--height", str(height),
        "--title",  _title, "--vertical-label", "bit/s",
        "--slope-mode", "--alt-autoscale-max", "--imgformat", "PNG",
        "--font", "TITLE:12:", "--font", "AXIS:9:",
        "--font", "LEGEND:9:", "--font", "UNIT:9:", "--units-length", "6",
    ]
    if log_scale:
        _cli_args += ["--logarithmic", "--lower-limit", "1"]
    elif style != "mirror":
        _cli_args += ["--lower-limit", "0"]
    _cli_args += [
        f"DEF:rx_raw={_rrd}:rx:AVERAGE",
        f"DEF:tx_raw={_rrd}:tx:AVERAGE",
    ]
    _cli_args += (["CDEF:rx=rx_raw,60,TREND","CDEF:tx=tx_raw,60,TREND"]
                  if smooth else ["CDEF:rx=rx_raw","CDEF:tx=tx_raw"])
    _cli_args += (["CDEF:rxplot=rx,1,MAX","CDEF:txsafe=tx,1,MAX"]
                  if log_scale else ["CDEF:rxplot=rx","CDEF:txsafe=tx"])
    _cli_args += (["CDEF:txplot=txsafe,-1,*"]
                  if style == "mirror" and not log_scale else ["CDEF:txplot=txsafe"])
    _cli_args += [
        "VDEF:rxavg=rx_raw,AVERAGE", "VDEF:rxmax=rx_raw,MAXIMUM",
        "VDEF:txavg=tx_raw,AVERAGE", "VDEF:txmax=tx_raw,MAXIMUM",
    ]
    if show_volume:
        _cli_args += [
            "CDEF:rx_bytes=rx_raw,8,/", "CDEF:tx_bytes=tx_raw,8,/",
            "VDEF:rxtotal=rx_bytes,TOTAL", "VDEF:txtotal=tx_bytes,TOTAL",
        ]
    _gp_avg_rx = "GPRINT:rxavg: avg" + r"\:" + "%6.2lf %Sbit/s"
    _gp_max_rx = "GPRINT:rxmax:  max" + r"\:" + "%6.2lf %Sbit/s"
    _gp_avg_tx = "GPRINT:txavg: avg" + r"\:" + "%6.2lf %Sbit/s"
    _gp_max_tx = "GPRINT:txmax:  max" + r"\:" + "%6.2lf %Sbit/s"
    _cm_vol_rx = ("GPRINT:rxtotal:  vol" + r"\:" + "%6.2lf %SB\\n") if show_volume else "COMMENT:\\n"
    _cm_vol_tx = ("GPRINT:txtotal:  vol" + r"\:" + "%6.2lf %SB\\n") if show_volume else "COMMENT:\\n"
    if style == "line":
        _cli_args += ["LINE2:rxplot#00cc66:RX ", _gp_avg_rx, _gp_max_rx, _cm_vol_rx,
                      "LINE2:txplot#3399ff:TX ", _gp_avg_tx, _gp_max_tx, _cm_vol_tx]
    elif style == "mirror":
        _cli_args += ["AREA:rxplot#99e6bb:RX ", "LINE1:rxplot#00aa55",
                      _gp_avg_rx, _gp_max_rx, _cm_vol_rx,
                      "AREA:txplot#b3d9ff:TX ", "LINE1:txplot#2277cc",
                      _gp_avg_tx, _gp_max_tx, _cm_vol_tx, "HRULE:0#666666"]
    else:
        _cli_args += ["AREA:rxplot#99e6bbB0:RX ", "LINE1:rxplot#00aa55",
                      _gp_avg_rx, _gp_max_rx, _cm_vol_rx,
                      "AREA:txplot#b3d9ffB0:TX ", "LINE1:txplot#2277cc",
                      _gp_avg_tx, _gp_max_tx, _cm_vol_tx]
    rrdtool_cmd = " ".join(shlex.quote(a) for a in _cli_args)

    body = header + f"""
<main>
  <form method="get" class="panel" id="controlForm">
    <input type="hidden" name="start"  id="startField" value="{graph_start}">
    <input type="hidden" name="end"    id="endField"   value="{graph_end}">
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
      <div style="flex:0 0 auto"><label>Time range</label>
        <select name="range" id="rangeSelect" onchange="clearCustomAndSubmit()" style="padding:7px 6px;width:auto">{ranges_html}</select></div>
      <div style="flex:0 0 auto"><label>Width</label>
        <input name="width"  id="widthField"  type="number" min="300" max="4000" value="{width}" style="padding:7px 4px;width:68px"></div>
      <div style="flex:0 0 auto"><label>Height</label>
        <input name="height" id="heightField" type="number" min="150" max="2000" value="{height}" style="padding:7px 4px;width:68px"></div>
      <div style="flex:0 0 auto"><label>Style</label>
        <select name="style" style="padding:7px 6px;width:auto">
          <option value="area"   {"selected" if style=="area"   else ""}>Area</option>
          <option value="line"   {"selected" if style=="line"   else ""}>Line</option>
          <option value="mirror" {"selected" if style=="mirror" else ""} {"disabled" if log_scale else ""}>Mirror</option>
        </select></div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:8px">
      <label style="margin:0;color:var(--text);font-size:13px"><input type="checkbox" name="smooth" value="1" {"checked" if smooth      else ""}> Smooth</label>
      <input type="hidden" name="volume" value="0">
      <label style="margin:0;color:var(--text);font-size:13px"><input type="checkbox" name="volume" value="1" {"checked" if show_volume else ""}> Volume</label>
      <div style="display:flex;align-items:center;gap:5px">
        <span style="color:var(--muted);font-size:12px">Refresh</span>
        <select name="refresh" id="refreshSelect" onchange="form.submit()" style="width:auto;padding:5px 8px;font-size:13px">
          <option value="0"  {"selected" if refresh_sec==0  else ""}>Off</option>
          <option value="5"  {"selected" if refresh_sec==5  else ""}>5s</option>
          <option value="30" {"selected" if refresh_sec==30 else ""}>30s</option>
          <option value="60" {"selected" if refresh_sec==60 else ""}>60s</option>
        </select>
      </div>
      <button type="submit" style="width:auto;padding:5px 14px;font-size:13px">Redraw</button>
      <button type="button" class="secondary" onclick="resizeGraph(1.25)" style="width:auto;padding:5px 10px;font-size:13px">Wider</button>
      <button type="button" class="secondary" onclick="resizeGraph(0.80)" style="width:auto;padding:5px 10px;font-size:13px">Narrower</button>
    </div>

  </form>

  <div class="panel graph-panel">
    <div class="graph-toolbar">
      <span style="color:var(--muted);font-size:13px">drag to zoom · <strong>{h(res['effective_label'])}</strong>/point · {h(res['pixel_label'])}/px</span>
      <span style="color:var(--muted);font-size:12px">{h(from_label)} → {h(to_label)}</span>
    </div>
    <div class="graph-frame">
      <div class="graph-holder" id="graphHolder">
        <img id="graph" src="?{h(img_query)}" alt="traffic graph"
             width="{width}" height="{height+120}" draggable="false">
        <div id="selection"></div>
      </div>
    </div>
  </div>

  <div class="panel" style="padding:12px 18px">
    <div style="display:flex;align-items:center;gap:10px">
      <span style="color:var(--muted);font-size:12px">Direct graph link:</span>
      <input id="graphLinkInput" type="text" readonly
             style="flex:1;font-size:11px;font-family:monospace;padding:6px 8px;color:var(--muted);cursor:text"
             value="">
      <button type="button" id="copyLinkBtn"
              onclick="copyGraphLink()"
              style="width:auto;padding:6px 14px;font-size:12px;white-space:nowrap">
        Copy link
      </button>
      <button type="button" id="copyRrdBtn"
              onclick="copyRrdCmd()"
              style="width:auto;padding:6px 14px;font-size:12px;white-space:nowrap;background:var(--panel2)">
        Copy rrdtool cmd
      </button>
    </div>
  </div>
</main>"""

    js = ("""
const graph=document.getElementById('graph'),selection=document.getElementById('selection');
const form=document.getElementById('controlForm');
const startField=document.getElementById('startField'),endField=document.getElementById('endField');
const rangeSelect=document.getElementById('rangeSelect');
const graphStart="""+ str(graph_start) +""",graphEnd="""+ str(graph_end) +""";
const plotLeft=75,plotRight=25;
let dragging=false,dragStartX=0,dragCurrentX=0;
function localX(e){return e.clientX-graph.getBoundingClientRect().left;}
function clampX(x){return Math.max(plotLeft,Math.min(graph.clientWidth-plotRight,x));}
function toEpoch(x){return Math.round(graphStart+(x-plotLeft)/(graph.clientWidth-plotRight-plotLeft)*(graphEnd-graphStart));}
function updateSel(){const a=clampX(dragStartX),b=clampX(dragCurrentX);
  selection.style.left=Math.min(a,b)+'px';selection.style.width=Math.abs(b-a)+'px';
  selection.style.display=Math.abs(b-a)>2?'block':'none';}
graph.addEventListener('mousedown',e=>{dragging=true;dragStartX=dragCurrentX=localX(e);updateSel();e.preventDefault();});
window.addEventListener('mousemove',e=>{if(!dragging)return;dragCurrentX=localX(e);updateSel();});
window.addEventListener('mouseup',()=>{
  if(!dragging)return;dragging=false;
  const a=clampX(dragStartX),b=clampX(dragCurrentX);
  if(Math.abs(b-a)<12){selection.style.display='none';return;}
  const ns=Math.min(toEpoch(a),toEpoch(b)),ne=Math.max(toEpoch(a),toEpoch(b));
  if(ne-ns<1){selection.style.display='none';return;}   // min 1s
  startField.value=String(ns);endField.value=String(ne);rangeSelect.value='custom';form.submit();});
function goRange(r){const u=new URL(window.location.href);
  u.searchParams.delete('start');u.searchParams.delete('end');
  u.searchParams.set('range',r);window.location.href=u.toString();}
function clearCustomAndSubmit(){
  if(rangeSelect.value!=='custom'){startField.removeAttribute('name');endField.removeAttribute('name');}
  form.submit();}
function resizeGraph(f){
  const w=document.getElementById('widthField'),h=document.getElementById('heightField');
  w.value=Math.max(300,Math.min(4000,Math.round(Number(w.value)*f)));
  h.value=Math.max(150,Math.min(2000,Math.round(Number(h.value)*f)));form.submit();}
function pollLive(){fetch('/live').then(r=>r.json()).then(d=>{
  const el=document.getElementById('liveStats');if(!el)return;
  const now=Date.now()/1000;
  const age=(d.ts!==null&&d.ts!==undefined)?Math.round(now-d.ts):null;
  let dot,tip;
  if(age===null){dot='⚫';tip='No data yet';}
  else if(age<5){dot='🟢';tip='Live';}
  else if(age<30){dot='🟡';tip=age+'s ago';}
  else{dot='🔴';tip='Stale — '+age+'s ago';}
  const ts=d.ts?new Date(d.ts*1000).toLocaleTimeString():'—';
  el.innerHTML=dot+' <span title="'+tip+'">\u2b07 RX <span>'+fmt(d.rx)+'</span>'
    +' &nbsp;\u2b06 TX <span>'+fmt(d.tx)+'</span>'
    +' &nbsp;<small style=\"color:var(--muted)\">'+ts+'</small></span>';
}).catch(()=>{
  const el=document.getElementById('liveStats');
  if(el) el.innerHTML='🔴 <span style=\"color:var(--muted)\">collector offline</span>';
});setTimeout(pollLive,2000);}
function fmt(v){if(v===null||v===undefined)return'—';
  if(v>=1e9)return(v/1e9).toFixed(2)+' Gbit/s';
  if(v>=1e6)return(v/1e6).toFixed(2)+' Mbit/s';
  if(v>=1e3)return(v/1e3).toFixed(1)+' kbit/s';return v+' bit/s';}
pollLive();
""" + f"""
// Auto-refresh: reload only the graph <img> at the chosen interval
(function(){{
  const ms={refresh_sec}*1000;
  if(!ms) return;
  setInterval(()=>{{
    const img=document.getElementById('graph');
    if(!img) return;
    const u=new URL(img.src,window.location.href);
    u.searchParams.set('_',Date.now());
    img.src=u.toString();
  }},ms);
}})();
""" + f"""
// Populate direct graph link input with clean URL (no cache-buster)
(function(){{
  const inp=document.getElementById('graphLinkInput');
  if(inp) inp.value=window.location.origin+'?{clean_query}';
}})();
function copyGraphLink(){{
  const inp=document.getElementById('graphLinkInput');
  const btn=document.getElementById('copyLinkBtn');
  if(!inp)return;
  const url=inp.value;
  if(navigator.clipboard&&navigator.clipboard.writeText){{
    navigator.clipboard.writeText(url).then(()=>_copyDone(btn)).catch(()=>_copyFallback(url,btn));
  }}else{{
    _copyFallback(url,btn);
  }}
}}
// rrdtool CLI command for the current graph
const rrdtoolCmd=""" + repr(rrdtool_cmd) + r""";
document.getElementById('copyRrdBtn') && (document.getElementById('copyRrdBtn').title = rrdtoolCmd);
function copyRrdCmd(){
  const btn=document.getElementById('copyRrdBtn');
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(rrdtoolCmd).then(()=>_copyDone(btn)).catch(()=>_copyFallback(rrdtoolCmd,btn));
  }else{ _copyFallback(rrdtoolCmd,btn); }
}
function _copyDone(btn){{
  const orig=btn.dataset.label||(btn.dataset.label=btn.textContent);
  btn.textContent='✓ Copied';
  btn.style.background='linear-gradient(180deg,#2a6e3a,#1e5229)';
  setTimeout(()=>{{btn.textContent=orig;btn.style.background='';}},2000);
}}
function _copyFallback(url,btn){{
  const ta=document.createElement('textarea');
  ta.value=url;ta.style.cssText='position:fixed;top:0;left:0;opacity:0';
  document.body.appendChild(ta);ta.focus();ta.select();
  try{{document.execCommand('copy');_copyDone(btn);}}
  catch(e){{btn.textContent='Select & copy manually';}}
  document.body.removeChild(ta);
}}
""")
    return page_shell(title, body, js)


# ---------------------------------------------------------------------------
# Graph image generation
# ---------------------------------------------------------------------------

def generate_graph(cfg: configparser.ConfigParser, params: dict) -> bytes:
    rrd_file  = cfg.get("storage","rrd_file")
    title     = cfg.get("web",    "page_title")
    range_    = params.get("range","1h")
    width     = max(300,  min(4000, int(params.get("width",  1200))))
    height    = max(150,  min(2000, int(params.get("height", 420))))
    style     = params.get("style","area")
    if style not in ("area","line","mirror"): style = "area"
    log_scale   = params.get("log",    "0") == "1"
    smooth      = params.get("smooth", "0") == "1"
    show_volume = params.get("volume", "1") == "1"
    if log_scale and style == "mirror": style = "area"

    try:
        graph_start = int(params["start"])
        graph_end   = int(params["end"])
        if graph_end <= graph_start: raise ValueError
    except (KeyError, ValueError):
        graph_end   = int(time.time())
        graph_start = graph_end - range_to_seconds(range_)

    res = resolution_for_window(graph_start, graph_end, width)
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    tmp.close()

    args = [tmp.name,
            "--start", str(graph_start), "--end", str(graph_end),
            "--step",  str(res["effective_step"]),
            "--width", str(width), "--height", str(height),
            "--title", title, "--vertical-label", "bit/s",
            "--slope-mode","--alt-autoscale-max","--imgformat","PNG",
            "--font","TITLE:12:","--font","AXIS:9:",
            "--font","LEGEND:9:","--font","UNIT:9:",
            "--units-length","6"]

    if cfg.get("web","dark_graph",fallback="true").strip().lower() not in ("false","0","no"):
        args += ["--color","BACK#1a1d26","--color","CANVAS#1a1d26",
                 "--color","GRID#404858","--color","MGRID#606878",
                 "--color","FONT#e0e4ee","--color","AXIS#808898",
                 "--color","FRAME#1a1d26","--color","ARROW#808898"]

    if log_scale: args += ["--logarithmic","--lower-limit","1"]
    elif style != "mirror": args += ["--lower-limit","0"]

    args += [f"DEF:rx_raw={rrd_file}:rx:AVERAGE",
             f"DEF:tx_raw={rrd_file}:tx:AVERAGE"]
    args += (["CDEF:rx=rx_raw,60,TREND","CDEF:tx=tx_raw,60,TREND"] if smooth
             else ["CDEF:rx=rx_raw","CDEF:tx=tx_raw"])
    args += (["CDEF:rxplot=rx,1,MAX","CDEF:txsafe=tx,1,MAX"] if log_scale
             else ["CDEF:rxplot=rx","CDEF:txsafe=tx"])
    args += (["CDEF:txplot=txsafe,-1,*"] if style=="mirror" and not log_scale
             else ["CDEF:txplot=txsafe"])

    # CDEF/VDEF for legend stats.
    # avg/max: reference rx_raw DEF directly (VDEF cannot use CDEF in older builds)
    # volume:  CDEF converts bit/s -> byte/s, VDEF TOTAL integrates over window.
    #          This is GUARANTEED consistent with the displayed average because
    #          it uses the exact same data points the graph renders.
    args += [
        "VDEF:rxavg=rx_raw,AVERAGE", "VDEF:rxmax=rx_raw,MAXIMUM",
        "VDEF:txavg=tx_raw,AVERAGE", "VDEF:txmax=tx_raw,MAXIMUM",
    ]
    # CDEF for byte/s from the raw DEF (not from rx CDEF) so VDEF TOTAL works.
    # VDEF:TOTAL requires a CDEF that traces back to a DEF; rx_raw qualifies.
    if show_volume:
        args += [
            "CDEF:rx_bytes=rx_raw,8,/",   # byte/s directly from the raw DEF
            "CDEF:tx_bytes=tx_raw,8,/",
            "VDEF:rxtotal=rx_bytes,TOTAL", # total bytes over the graph window
            "VDEF:txtotal=tx_bytes,TOTAL",
        ]

    # rrdtool GPRINT format strings.
    # \: escapes the colon; %6.2lf %Sbit/s is 6-wide, 2dp, SI-scaled.
    # --units-length 6 (set above) gives a stable SI prefix column.
    gp_avg_rx = "GPRINT:rxavg: avg" + r"\:" + "%6.2lf %Sbit/s"
    gp_max_rx = "GPRINT:rxmax:  max" + r"\:" + "%6.2lf %Sbit/s"
    gp_avg_tx = "GPRINT:txavg: avg" + r"\:" + "%6.2lf %Sbit/s"
    gp_max_tx = "GPRINT:txmax:  max" + r"\:" + "%6.2lf %Sbit/s"

    if show_volume:
        # GPRINT on VDEF: no CF — just GPRINT:vdefname:format.
        # %6.2lf %SB auto-scales: kB → MB → GB → TB.
        cm_vol_rx = "GPRINT:rxtotal:  vol" + r"\:" + r"%6.2lf %SB\n"
        cm_vol_tx = "GPRINT:txtotal:  vol" + r"\:" + r"%6.2lf %SB\n"
    else:
        cm_vol_rx = r"COMMENT:\n"
        cm_vol_tx = r"COMMENT:\n"

    if style == "line":
        args += [
            "LINE2:rxplot#00cc66:RX ", gp_avg_rx, gp_max_rx, cm_vol_rx,
            "LINE2:txplot#3399ff:TX ", gp_avg_tx, gp_max_tx, cm_vol_tx,
        ]
    elif style == "mirror":
        # Mirror: fills go opposite directions — no overlap possible, full opacity
        args += [
            "AREA:rxplot#99e6bb:RX ", "LINE1:rxplot#00aa55",
            gp_avg_rx, gp_max_rx, cm_vol_rx,
            "AREA:txplot#b3d9ff:TX ", "LINE1:txplot#2277cc",
            gp_avg_tx, gp_max_tx, cm_vol_tx,
            "HRULE:0#666666",
        ]
    else:  # area: both semi-transparent (0xB0 ~69%) so overlap is visible
        args += [
            "AREA:rxplot#99e6bbB0:RX ", "LINE1:rxplot#00aa55",
            gp_avg_rx, gp_max_rx, cm_vol_rx,
            "AREA:txplot#b3d9ffB0:TX ", "LINE1:txplot#2277cc",
            gp_avg_tx, gp_max_tx, cm_vol_tx,
        ]
    result_holder = [None]
    exc_holder    = [None]

    def _run():
        try:
            rrdtool.graph(*args)
            with open(tmp.name,"rb") as f:
                result_holder[0] = f.read()
        except Exception as e:
            exc_holder[0] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=15)
    try: os.unlink(tmp.name)
    except OSError: pass
    if t.is_alive():
        raise TimeoutError("rrdtool graph timed out after 15 s")
    if exc_holder[0]:
        raise exc_holder[0]
    return result_holder[0]


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_acl_lock = threading.Lock()

def _build_acl() -> list:
    """Return cached parsed ACL, rebuilding only when cfg has changed."""
    with _acl_lock:
        if STATE._acl_cache is None or STATE._acl_cfg_ver != id(STATE.cfg):
            STATE._acl_cache   = parse_acl(STATE.cfg.get("web","allow",fallback=DEFAULT_ALLOW))
            STATE._acl_cfg_ver = id(STATE.cfg)
        return STATE._acl_cache


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        logging.debug("HTTP %s", fmt % args)

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str, code: int = 200) -> None:
        self._send(code, "text/html; charset=utf-8", body.encode())

    def _check_acl(self) -> bool:
        client_ip = self.client_address[0]
        if not is_allowed(client_ip, _build_acl()):
            logging.warning("Access denied for %s", client_ip)
            self._send(403, "text/plain",
                       f"403 Forbidden — {client_ip} is not in the allowed list.\n".encode())
            return False
        return True

    def do_GET(self):
        if not self._check_acl(): return
        parsed = urllib.parse.urlparse(self.path)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        path   = parsed.path.rstrip("/") or "/"

        if not STATE.setup_done.is_set() and path not in ("/setup","/favicon.ico"):
            self._html(build_setup_page(STATE.cfg,
                "Setup required — please fill in the configuration below."))
            return

        # Graph image — must be checked before path=="/" to avoid swallowing it
        if params.get("graph") == "1":
            if rrd_checks(STATE.cfg.get("storage","rrd_file")):
                self._send(500,"text/plain",b"RRD file not available"); return
            try:
                self._send(200,"image/png",generate_graph(STATE.cfg,params))
            except Exception as e:
                logging.error("Graph failed: %s", e)
                self._send(500,"text/plain",str(e).encode())
            return

        if   path == "/":               self._html(build_graph_page(STATE.cfg, params))
        elif path == "/setup":          self._html(build_setup_page(STATE.cfg))
        elif path == "/api/interfaces": self._serve_interfaces()
        elif path == "/live":
            with STATE.lock:
                data = json.dumps({
                    "rx": STATE.last_rx,
                    "tx": STATE.last_tx,
                    "ts": STATE.last_ts,   # None until first sample
                })
            self._send(200,"application/json",data.encode())
        else:
            self._send(404,"text/plain",b"Not found")

    def _serve_interfaces(self):
        """Return JSON list of interface names from the router (for setup dropdown)."""
        cfg  = STATE.cfg
        host = cfg.get("router","host",fallback="")
        user = cfg.get("router","user",fallback="")
        pw   = get_password(cfg)
        if not all([host, user, pw]):
            self._send(200,"application/json",b'{"error":"not configured"}'); return
        api = None
        try:
            api    = ros_connect(host=host, username=user, password=pw, timeout=5)
            ifaces = sorted(r.get("name","") for r in api.path("interface") if r.get("name"))
            self._send(200,"application/json",
                       json.dumps({"interfaces": ifaces}).encode())
        except Exception as e:
            self._send(200,"application/json",
                       json.dumps({"error": str(e)}).encode())
        finally:
            if api is not None:
                try: api.close()
                except Exception: pass

    def do_POST(self):
        if not self._check_acl(): return
        if urllib.parse.urlparse(self.path).path.rstrip("/") != "/setup":
            self._send(405,"text/plain",b"Method not allowed"); return

        ct = self.headers.get("Content-Type","")
        if "application/x-www-form-urlencoded" not in ct:
            self._send(415,"text/plain",b"415 Unsupported Media Type\n"); return

        length = int(self.headers.get("Content-Length",0))
        if length > 65536:
            self._send(413,"text/plain",b"Request too large"); return
        fields = dict(urllib.parse.parse_qsl(
            self.rfile.read(length).decode("utf-8",errors="replace")))

        # CSRF: reject requests that don't carry the current session token
        if not secrets.compare_digest(
                fields.get("csrf_token",""), STATE.csrf_token):
            self._send(403,"text/plain",b"403 Forbidden\n"); return

        action = fields.get("action","save")

        local = copy.deepcopy(STATE.cfg)

        # Carry forward existing active password if field left blank
        if not fields.get("password_plain","").strip():
            fields["password_plain"] = get_password(local)
        apply_fields(local, fields)

        # Active password is now in local["router"]["password_plain"]
        active_pw = local["router"]["password_plain"]

        if action == "test":
            ok, msg = test_router(local["router"]["host"], local["router"]["user"],
                                  active_pw, local["router"]["interface"])
            self._html(build_setup_page(local, msg, msg_ok=ok)); return

        # Save
        ok, msg = test_router(local["router"]["host"], local["router"]["user"],
                              active_pw, local["router"]["interface"])
        if not ok:
            self._html(build_setup_page(local,
                f"Connection test failed — {msg}. Fix the values and try again.")); return

        old_port     = validate_port(STATE.cfg.get("web","port",fallback="8080"))
        new_port     = validate_port(local.get("web","port",fallback="8080"))
        already_done = STATE.setup_done.is_set()
        web_enabled  = local.get("web","enabled",fallback="true").strip().lower() \
                       not in ("false","0","no")

        STATE.cfg = local
        save_config(local)
        # Invalidate ACL cache and signal collector when settings change
        with _acl_lock:
            STATE._acl_cache   = None
            STATE._acl_cfg_ver = 0
        if already_done:
            STATE.reconnect_event.set()

        if not already_done:
            STATE.setup_done.set()
            threading.Thread(target=collector_loop, daemon=True).start()

        port_changed = (new_port != old_port) and web_enabled

        if port_changed:
            # Port is changing: send a page with a countdown redirect to new port/main
            self._html(build_setup_page(
                local,
                "Settings saved." + ("" if already_done else " Collector started.")
                + f" Restarting on port {new_port}…",
                msg_ok=True,
                redirect_port=new_port,
            ))
            # Small delay so the response is fully sent before socket closes
            threading.Timer(0.5, request_server_restart, args=(new_port,)).start()
        elif not web_enabled and already_done:
            # Web server being disabled — show confirmation, then shut down
            self._html(build_setup_page(local, "Settings saved. Web server stopping.",
                                        msg_ok=True))
            threading.Timer(0.5, request_server_shutdown).start()
        else:
            # Normal save (same port, web still enabled) — redirect straight to main page
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

def collector_loop() -> None:
    STATE.setup_done.wait()
    _backoff = 5
    _reconnect_requested = False
    while True:
        cfg      = STATE.cfg
        rrd_file = cfg.get("storage","rrd_file")
        host     = cfg.get("router","host")
        user     = cfg.get("router","user")
        password = get_password(cfg)
        iface    = cfg.get("router","interface")
        api      = None
        _reconnect_requested = False
        try:
            init_rrd(rrd_file)
            api = ros_connect(host=host, username=user, password=password, timeout=10)
            logging.info("Connected to MikroTik %s, monitoring %s", host, iface)
            _backoff = 5    # reset backoff on successful connect
            while True:
                if STATE.reconnect_event.is_set():
                    STATE.reconnect_event.clear()
                    _reconnect_requested = True
                    logging.info("Settings changed — reconnecting collector")
                    break
                rows = tuple(api.path("interface")("monitor-traffic",
                                                   interface=iface, once=True))
                if not rows: raise RuntimeError("No data from monitor-traffic")
                row = rows[0]
                rx  = int(row.get("rx-bits-per-second",0))
                tx  = int(row.get("tx-bits-per-second",0))
                ts  = time.time()
                try:
                    rrdtool.update(rrd_file, f"N:{rx}:{tx}")
                except rrdtool.error as e:
                    logging.warning("RRD update skipped: %s", e)
                with STATE.lock:
                    STATE.last_rx, STATE.last_tx, STATE.last_ts = rx, tx, ts
                logging.debug("RX=%d TX=%d", rx, tx)
                now = time.time()
                time.sleep(max(0.0, 1.0-(now%1.0)))
        except Exception as e:
            logging.error("Collector error: %s — retrying in %d s", e, _backoff)
        finally:
            if api is not None:
                try: api.close()
                except Exception: pass
        if not _reconnect_requested:
            # Exponential backoff: 5 s → 10 → 20 → 40 → 60 (cap)
            time.sleep(_backoff)
            _backoff = min(_backoff * 2, 60)


# ---------------------------------------------------------------------------
# Config file watcher (C4+F11)
# ---------------------------------------------------------------------------

def config_watcher_loop() -> None:
    """Poll mt-trafmon.ini mtime every 30 s.
    On change: reload cfg, invalidate ACL cache, signal collector to reconnect."""
    STATE.setup_done.wait()
    last_mtime = None
    while not STATE._shutdown_flag:
        try:
            mtime = CONFIG_FILE.stat().st_mtime if CONFIG_FILE.exists() else None
            if mtime is not None and mtime != last_mtime:
                if last_mtime is not None:          # skip the first read
                    logging.info("Config file changed — reloading")
                    new_cfg = load_config()
                    STATE.cfg = new_cfg
                    # Invalidate ACL cache
                    with _acl_lock:
                        STATE._acl_cache   = None
                        STATE._acl_cfg_ver = 0
                    # Signal collector to reconnect with new settings
                    STATE.reconnect_event.set()
                last_mtime = mtime
        except Exception as e:
            logging.debug("Config watcher error: %s", e)
        time.sleep(30)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="MikroTik traffic monitor")
    parser.add_argument("-q","--quiet",   action="store_true",
                        help="suppress per-sample log output")
    parser.add_argument("-s","--setup",   action="store_true",
                        help="force setup wizard")
    parser.add_argument("-v","--version",  action="store_true",
                        help="print version (script modification date) and exit")
    parser.add_argument("-w","--web-only", action="store_true",
                        help="run web server only — do not collect data "
                             "(serve graphs from an existing RRD file)")
    args = parser.parse_args()

    if args.version:
        try:
            mtime = pathlib.Path(__file__).stat().st_mtime
            print(f"mt-trafmon  (modified {time.strftime('%Y-%m-%d', time.localtime(mtime))})")
        except OSError:
            print("mt-trafmon  (version unknown)")
        sys.exit(0)

    logging.basicConfig(
        level   = logging.WARNING if args.quiet else logging.INFO,
        format  = "%(asctime)s %(levelname)s %(message)s",
        stream  = sys.stderr,
    )

    cfg = load_config()
    STATE.cfg = cfg

    needs_setup = args.setup or not config_is_complete(cfg)

    # ── Setup phase (blocking, CLI only) ──────────────────────────────────
    if needs_setup:
        if not sys.stdin.isatty():
            logging.error(
                "Setup required but no TTY available. "
                "Run interactively or place a valid mt-trafmon.ini next to the script.")
            sys.exit(1)
        cfg = tty_setup(cfg)
        STATE.cfg = cfg

    STATE.setup_done.set()

    web_enabled = cfg.get("web","enabled",fallback="true").strip().lower() \
                  not in ("false","0","no")

    if not web_enabled:
        logging.info("Web server disabled — collector-only mode")
        threading.Thread(target=config_watcher_loop, daemon=True).start()
        collector_loop()                   # blocks forever
        return

    # ── Normal operation: web server, optionally with collector ──────────
    if not getattr(args, "web_only", False):
        threading.Thread(target=collector_loop, daemon=True).start()
    else:
        logging.info("Web-only mode — not collecting data")

    # Config file watcher — reloads on manual ini edits
    threading.Thread(target=config_watcher_loop, daemon=True).start()

    # Main thread: serve_forever loop — restarts automatically if port changes
    _ctrl_c_count = [0]

    def _signal_shutdown(sig, frame):
        _ctrl_c_count[0] += 1
        if _ctrl_c_count[0] == 1:
            logging.info("Signal received — shutting down…")
            STATE._shutdown_flag = True
            # Trigger shutdown in a new thread so signal handler returns immediately
            with STATE._srv_lock:
                srv = STATE._server
            if srv:
                threading.Thread(target=srv.shutdown, daemon=True).start()
        else:
            # Second CTRL-C: emergency exit
            logging.warning("Forced exit.")
            os._exit(1)

    signal.signal(signal.SIGTERM, _signal_shutdown)
    signal.signal(signal.SIGINT,  _signal_shutdown)

    class _Server(ThreadingHTTPServer):
        allow_reuse_address = True
        allow_reuse_port    = True   # SO_REUSEPORT — avoids TIME_WAIT on rebind
        daemon_threads      = True   # don't block shutdown waiting for request threads

        # Bounded pool — max 20 concurrent request threads (V2)
        _pool = concurrent.futures.ThreadPoolExecutor(max_workers=20)

        def process_request(self, request, client_address):
            self._pool.submit(self.process_request_thread, request, client_address)

        def server_close(self):
            super().server_close()
            self._pool.shutdown(wait=False)

    while not STATE._shutdown_flag:
        port = validate_port(STATE.cfg.get("web","port",fallback="8080"))
        logging.info("Starting web server on port %d", port)

        # Brief pause so the OS releases the previous socket before rebinding
        time.sleep(0.2)

        server = _Server(("0.0.0.0", port), Handler)
        with STATE._srv_lock:
            STATE._server       = server
            STATE._restart_port = None

        server.serve_forever()          # blocks until shutdown() is called

        with STATE._srv_lock:
            restart_port  = STATE._restart_port
            STATE._server = None

        if STATE._shutdown_flag:
            logging.info("Web server stopped.")
            break

        if restart_port is not None:
            logging.info("Restarting web server on port %d…", restart_port)
            continue   # loop reads new port from STATE.cfg

        break   # unexpected exit


if __name__ == "__main__":
    main()
