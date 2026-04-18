"""
Task 3: Deception-Based Security Mechanism
A honeypot system with GUI that traps and logs suspicious/malicious activity.

Components:
  1. Honeypot Login Interface  - fake login page that flags anyone who tries it
  2. Dummy API Endpoint Monitor - simulated service that catches unauthorized calls
  3. Concealed Honey-File       - bait file whose access is tracked
  4. Alert Dashboard            - real-time activity log with threat classification
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import datetime
import random
import time
import json
import os
import hashlib
import socket
import http.server
import socketserver

# ──────────────────────────────────────────────
#  GLOBAL STATE
# ──────────────────────────────────────────────
alerts = []          # list of alert dicts
alert_lock = threading.Lock()
honey_file_path = "honey_document_CONFIDENTIAL.txt"
dummy_api_port   = 8765
api_server_thread = None
api_server_obj    = None

# ── Threat Intelligence State ──────────────────
# ip_stats[ip] = {"count": int, "sources": set, "first_seen": str, "last_seen": str,
#                 "blocked": bool, "last_ts": float}
ip_stats      = {}
ip_stats_lock = threading.Lock()

ATTEMPT_WARN_THRESHOLD     = 3   # triggers a brute-force WARNING alert
ATTEMPT_CRITICAL_THRESHOLD = 5   # auto-escalates + marks IP as blocked
REPEATED_ATTACK_WINDOW     = 60  # seconds – repeated-attack detection window

SEVERITY_COLORS = {
    "LOW":      "#f0c040",
    "MEDIUM":   "#e07020",
    "HIGH":     "#e03030",
    "CRITICAL": "#cc00cc",
}

# ──────────────────────────────────────────────
#  THREAT INTELLIGENCE ENGINE
# ──────────────────────────────────────────────
def _update_ip_stats(ip: str, source: str) -> dict:
    """Update per-IP counters and return the current stats dict for that IP."""
    now_ts  = time.time()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with ip_stats_lock:
        if ip not in ip_stats:
            ip_stats[ip] = {
                "count":      0,
                "sources":    set(),
                "first_seen": now_str,
                "last_seen":  now_str,
                "last_ts":    now_ts,
                "blocked":    False,
            }
        rec = ip_stats[ip]
        rec["count"]    += 1
        rec["sources"].add(source)
        rec["last_seen"] = now_str
        rec["last_ts"]   = now_ts
        return dict(rec)   # return a copy (sets not JSON-serialisable, convert later)


def add_alert(source: str, detail: str, severity: str = "HIGH", ip: str = "127.0.0.1"):
    """Add an alert, run threat-intelligence checks, and auto-escalate if needed."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Update IP intelligence
    rec = _update_ip_stats(ip, source)
    count = rec["count"]

    # ── Rule 1: Too many attempts → escalate to CRITICAL ──────────────────
    if count >= ATTEMPT_CRITICAL_THRESHOLD and severity not in ("CRITICAL",):
        severity = "CRITICAL"
        detail   = f"[🔴 BRUTE-FORCE / FLOOD – attempt #{count}] " + detail

    elif count >= ATTEMPT_WARN_THRESHOLD and severity == "LOW":
        severity = "MEDIUM"
        detail   = f"[⚠ REPEAT #{count}] " + detail

    # ── Rule 2: Repeated-attack detection (same IP, same window) ──────────
    # If this is NOT the first hit but the IP has been seen before and is
    # now back within the time window, prepend a repeated-attack tag.
    if count > 1 and severity not in ("CRITICAL",):
        detail = f"[🔁 REPEAT ATTACKER – {count} hits] " + detail

    entry = {
        "time":     ts,
        "source":   source,
        "detail":   detail,
        "severity": severity,
        "ip":       ip,
        "ip_count": count,
    }
    with alert_lock:
        alerts.append(entry)

    # ── Rule 3: Auto-block IP when threshold exceeded ─────────────────────
    if count == ATTEMPT_CRITICAL_THRESHOLD:
        _block_ip(ip)
        # Inject a synthetic "BLOCKED" alert
        block_entry = {
            "time":     ts,
            "source":   "Threat Engine",
            "detail":   f"🚫 IP {ip} AUTO-BLOCKED after {count} trap interactions (sources: {', '.join(rec['sources'])})",
            "severity": "CRITICAL",
            "ip":       ip,
            "ip_count": count,
        }
        with alert_lock:
            alerts.append(block_entry)

    return entry


def _block_ip(ip: str):
    with ip_stats_lock:
        if ip in ip_stats:
            ip_stats[ip]["blocked"] = True


def get_ip_summary():
    """Return a sorted list of (ip, stats_dict) for the UI."""
    with ip_stats_lock:
        result = []
        for ip, rec in ip_stats.items():
            result.append((ip, {
                "count":      rec["count"],
                "sources":    ", ".join(sorted(rec["sources"])),
                "first_seen": rec["first_seen"],
                "last_seen":  rec["last_seen"],
                "blocked":    rec["blocked"],
            }))
    result.sort(key=lambda x: x[1]["count"], reverse=True)
    return result

# ──────────────────────────────────────────────
#  HONEY FILE
# ──────────────────────────────────────────────
def create_honey_file():
    """Create the bait file if it doesn't exist."""
    if not os.path.exists(honey_file_path):
        with open(honey_file_path, "w") as f:
            f.write("=== TOP SECRET – INTERNAL USE ONLY ===\n")
            f.write("Project Codename: PHANTOM\n")
            f.write("Credentials: admin / P@ssw0rd!2025\n")
            f.write("Server IPs: 10.0.0.1, 10.0.0.2, 10.0.0.5\n")
            f.write("This file is MONITORED. Any access is logged.\n")

def get_honey_file_mtime():
    try:
        return os.path.getmtime(honey_file_path)
    except Exception:
        return None

# ──────────────────────────────────────────────
#  DUMMY API HTTP SERVER
# ──────────────────────────────────────────────
class HoneypotAPIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ip = self.client_address[0]
        path = self.path
        add_alert(
            source   = "Dummy API",
            detail   = f"GET request to honey-endpoint '{path}'",
            severity = "CRITICAL",
            ip       = ip,
        )
        # Return a plausible-looking fake JSON response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        payload = json.dumps({"status": "ok", "token": hashlib.md5(os.urandom(8)).hexdigest()})
        self.wfile.write(payload.encode())

    def do_POST(self):
        ip   = self.client_address[0]
        path = self.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        add_alert(
            source   = "Dummy API",
            detail   = f"POST request to honey-endpoint '{path}' | Body: {body[:120]}",
            severity = "CRITICAL",
            ip       = ip,
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"accepted"}')

    def log_message(self, format, *args):
        pass   # suppress console noise


def start_dummy_api():
    global api_server_obj
    try:
        api_server_obj = socketserver.TCPServer(("127.0.0.1", dummy_api_port), HoneypotAPIHandler)
        api_server_obj.allow_reuse_address = True
        api_server_obj.serve_forever()
    except OSError:
        pass   # port already in use – skip silently

# ──────────────────────────────────────────────
#  MAIN APPLICATION
# ──────────────────────────────────────────────
class DeceptionSecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Deception-Based Security Mechanism – Honeypot Dashboard")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg="#0d1117")
        self._honey_mtime = get_honey_file_mtime()
        self._build_ui()
        self._start_background_tasks()
        self._refresh_alerts()    # kick off periodic UI refresh
        self._refresh_intel()     # kick off per-IP intel refresh

    # ── UI BUILD ──────────────────────────────
    def _build_ui(self):
        # ── Header ────────────────────────────
        hdr = tk.Frame(self, bg="#161b22", pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🛡  HONEYPOT SECURITY DASHBOARD",
                 font=("Courier New", 18, "bold"),
                 fg="#58a6ff", bg="#161b22").pack(side="left", padx=20)
        self._status_lbl = tk.Label(hdr, text="● ACTIVE",
                                    font=("Courier New", 11, "bold"),
                                    fg="#3fb950", bg="#161b22")
        self._status_lbl.pack(side="right", padx=20)

        # ── Notebook tabs ─────────────────────
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("TNotebook",           background="#0d1117", borderwidth=0)
        style.configure("TNotebook.Tab",       background="#161b22", foreground="#8b949e",
                                               font=("Courier New", 10, "bold"), padding=[14, 6])
        style.map("TNotebook.Tab",
                  background=[("selected", "#1f6feb")],
                  foreground=[("selected", "#ffffff")])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(8, 0))

        # Tab 1 – Honeypot Login
        self._tab_login = tk.Frame(nb, bg="#0d1117")
        nb.add(self._tab_login, text="  🪤  Honeypot Login  ")
        self._build_login_tab()

        # Tab 2 – Alert Dashboard
        self._tab_alerts = tk.Frame(nb, bg="#0d1117")
        nb.add(self._tab_alerts, text="  🚨  Alert Dashboard  ")
        self._build_alerts_tab()

        # Tab 3 – Honey File Monitor
        self._tab_file = tk.Frame(nb, bg="#0d1117")
        nb.add(self._tab_file, text="  📄  Honey File  ")
        self._build_file_tab()

        # Tab 4 – Dummy API Monitor
        self._tab_api = tk.Frame(nb, bg="#0d1117")
        nb.add(self._tab_api, text="  🌐  Dummy API  ")
        self._build_api_tab()

        # Tab 5 – Threat Intelligence
        self._tab_intel = tk.Frame(nb, bg="#0d1117")
        nb.add(self._tab_intel, text="  🧠  Threat Intel  ")
        self._build_intel_tab()



        # ── Status bar ────────────────────────
        bar = tk.Frame(self, bg="#161b22", pady=4)
        bar.pack(fill="x", side="bottom")
        self._bar_lbl = tk.Label(bar,
                                 text="System initialising…",
                                 font=("Courier New", 9),
                                 fg="#8b949e", bg="#161b22", anchor="w")
        self._bar_lbl.pack(fill="x", padx=14)

    # ── TAB 1: HONEYPOT LOGIN ─────────────────
    def _build_login_tab(self):
        f = self._tab_login
        tk.Label(f, text="Fake Login Portal  (any interaction triggers an alert)",
                 font=("Courier New", 12), fg="#8b949e", bg="#0d1117").pack(pady=(18, 4))

        card = tk.Frame(f, bg="#161b22", bd=0, highlightthickness=1,
                        highlightbackground="#30363d")
        card.pack(pady=10, ipadx=30, ipady=20)

        tk.Label(card, text="🔐  Internal Admin Portal",
                 font=("Courier New", 15, "bold"),
                 fg="#58a6ff", bg="#161b22").grid(row=0, column=0, columnspan=2, pady=(10, 18))

        lbl_opts = dict(font=("Courier New", 11), fg="#c9d1d9", bg="#161b22", anchor="w")
        ent_opts  = dict(font=("Courier New", 11), bg="#0d1117", fg="#c9d1d9",
                         insertbackground="white", relief="flat",
                         highlightthickness=1, highlightbackground="#30363d", width=26)

        tk.Label(card, text="Username:", **lbl_opts).grid(row=1, column=0, sticky="w", padx=10, pady=6)
        self._hn_user = tk.Entry(card, **ent_opts)
        self._hn_user.grid(row=1, column=1, padx=10, pady=6)

        tk.Label(card, text="Password:", **lbl_opts).grid(row=2, column=0, sticky="w", padx=10, pady=6)
        self._hn_pass = tk.Entry(card, show="●", **ent_opts)
        self._hn_pass.grid(row=2, column=1, padx=10, pady=6)

        # Bind typing events – flag as soon as user starts interacting
        self._hn_user.bind("<FocusIn>",  self._honeypot_interact)
        self._hn_pass.bind("<FocusIn>",  self._honeypot_interact)
        self._hn_user.bind("<KeyPress>", self._honeypot_interact)
        self._hn_pass.bind("<KeyPress>", self._honeypot_interact)

        btn = tk.Button(card, text="  Login  ",
                        font=("Courier New", 11, "bold"),
                        bg="#1f6feb", fg="white", activebackground="#388bfd",
                        relief="flat", cursor="hand2", command=self._honeypot_login)
        btn.grid(row=3, column=0, columnspan=2, pady=(14, 6))

        self._hn_result = tk.Label(card, text="", font=("Courier New", 10),
                                   fg="#f85149", bg="#161b22")
        self._hn_result.grid(row=4, column=0, columnspan=2, pady=4)

        # Trap stats
        stats = tk.Frame(f, bg="#0d1117")
        stats.pack(pady=12)
        self._login_hits = tk.IntVar(value=0)
        tk.Label(stats, text="Total login trap hits:", font=("Courier New", 11),
                 fg="#8b949e", bg="#0d1117").pack(side="left")
        tk.Label(stats, textvariable=self._login_hits, font=("Courier New", 13, "bold"),
                 fg="#f85149", bg="#0d1117").pack(side="left", padx=6)

        self._hn_interacted = False   # flag to avoid duplicate "focus" alerts

        # Brute-force warning banner (hidden until threshold hit)
        self._bf_banner = tk.Label(f,
            text="",
            font=("Courier New", 11, "bold"),
            fg="#0d1117", bg="#cc00cc",
            pady=6)
        self._bf_banner.pack(fill="x", padx=20)

    def _honeypot_interact(self, event=None):
        if not self._hn_interacted:
            self._hn_interacted = True
            add_alert("Honeypot Login",
                      "User began interacting with fake login form (typed/focused).",
                      severity="MEDIUM")

    def _honeypot_login(self):
        user = self._hn_user.get()
        pwd  = self._hn_pass.get()
        hits = self._login_hits.get() + 1
        self._login_hits.set(hits)

        # Simulate a consistent source IP (cycles through a small pool to demo repeat detection)
        sim_ip = random.choice(["192.168.1.101", "192.168.1.101", "10.0.0.45"])

        add_alert("Honeypot Login",
                  f"Login attempt — username='{user}' password='{pwd}'",
                  severity="CRITICAL", ip=sim_ip)

        # Update brute-force banner
        with ip_stats_lock:
            count = ip_stats.get(sim_ip, {}).get("count", hits)
        if count >= ATTEMPT_CRITICAL_THRESHOLD:
            self._bf_banner.config(
                text=f"🚫  BRUTE-FORCE DETECTED — IP {sim_ip} AUTO-BLOCKED after {count} attempts")
        elif count >= ATTEMPT_WARN_THRESHOLD:
            self._bf_banner.config(
                text=f"⚠  WARNING — {count} repeated login attempts from {sim_ip}",
                bg="#e07020")
        else:
            self._bf_banner.config(text="", bg="#cc00cc")

        self._hn_result.config(text="⚠ Authentication failed. Incident logged.")
        self._hn_user.delete(0, "end")
        self._hn_pass.delete(0, "end")
        self._hn_interacted = False

    # ── TAB 2: ALERT DASHBOARD ────────────────
    def _build_alerts_tab(self):
        f = self._tab_alerts
        top = tk.Frame(f, bg="#0d1117")
        top.pack(fill="x", padx=14, pady=(12, 4))
        tk.Label(top, text="Live Threat Feed", font=("Courier New", 13, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(side="left")
        tk.Button(top, text=" 🗑  Clear ", font=("Courier New", 9),
                  bg="#21262d", fg="#c9d1d9", relief="flat",
                  command=self._clear_alerts, cursor="hand2").pack(side="right")
        tk.Button(top, text=" 💾  Export ", font=("Courier New", 9),
                  bg="#21262d", fg="#c9d1d9", relief="flat",
                  command=self._export_alerts, cursor="hand2").pack(side="right", padx=6)

        cols = ("Time", "Source", "Severity", "IP", "Detail")
        self._tree = ttk.Treeview(f, columns=cols, show="headings", height=20)
        style = ttk.Style()
        style.configure("Treeview",
                        background="#161b22", foreground="#c9d1d9",
                        rowheight=26, fieldbackground="#161b22",
                        font=("Courier New", 9))
        style.configure("Treeview.Heading",
                        background="#21262d", foreground="#58a6ff",
                        font=("Courier New", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1f6feb")])

        widths = [140, 130, 80, 110, 520]
        for col, w in zip(cols, widths):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, anchor="w")

        sb = ttk.Scrollbar(f, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True, padx=(14, 0), pady=(0, 10))
        sb.pack(side="left", fill="y", pady=(0, 10))

        # Tag colours per severity
        for sev, col in SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, foreground=col)

        self._known_alert_count = 0

    def _clear_alerts(self):
        with alert_lock:
            alerts.clear()
        with ip_stats_lock:
            ip_stats.clear()
        self._tree.delete(*self._tree.get_children())
        self._known_alert_count = 0
        self._ip_tree_snapshot.clear()
        self._bf_banner.config(text="", bg="#cc00cc")
        self._login_hits.set(0)

    def _export_alerts(self):
        fname = f"honeypot_alerts_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with alert_lock:
            data = list(alerts)
        with open(fname, "w") as fh:
            json.dump(data, fh, indent=2)
        messagebox.showinfo("Export", f"Alerts exported to:\n{os.path.abspath(fname)}")

    # ── TAB 3: HONEY FILE ─────────────────────
    def _build_file_tab(self):
        f = self._tab_file
        tk.Label(f, text="Honey File Monitor",
                 font=("Courier New", 13, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(pady=(18, 4), anchor="w", padx=20)

        info = tk.Frame(f, bg="#161b22", highlightthickness=1,
                        highlightbackground="#30363d")
        info.pack(fill="x", padx=20, pady=8, ipady=8)
        tk.Label(info, text=f"Bait file path:  {os.path.abspath(honey_file_path)}",
                 font=("Courier New", 10), fg="#c9d1d9", bg="#161b22").pack(anchor="w", padx=12, pady=4)
        tk.Label(info, text="Any modification or access to this file triggers a HIGH alert.",
                 font=("Courier New", 10), fg="#8b949e", bg="#161b22").pack(anchor="w", padx=12)

        btn_row = tk.Frame(f, bg="#0d1117")
        btn_row.pack(pady=10)
        tk.Button(btn_row, text=" 📂 Simulate Access ",
                  font=("Courier New", 10, "bold"),
                  bg="#1f6feb", fg="white", relief="flat", cursor="hand2",
                  command=self._simulate_file_access).pack(side="left", padx=6)
        tk.Button(btn_row, text=" ✏  Simulate Modify ",
                  font=("Courier New", 10, "bold"),
                  bg="#da3633", fg="white", relief="flat", cursor="hand2",
                  command=self._simulate_file_modify).pack(side="left", padx=6)

        tk.Label(f, text="File Content Preview (bait data):",
                 font=("Courier New", 10, "bold"),
                 fg="#8b949e", bg="#0d1117").pack(anchor="w", padx=20, pady=(10, 2))
        self._file_preview = scrolledtext.ScrolledText(f, height=10,
                                                        font=("Courier New", 10),
                                                        bg="#161b22", fg="#c9d1d9",
                                                        insertbackground="white", state="disabled",
                                                        relief="flat")
        self._file_preview.pack(fill="x", padx=20)
        self._refresh_file_preview()

        self._file_hits_var = tk.IntVar(value=0)
        row2 = tk.Frame(f, bg="#0d1117")
        row2.pack(pady=8)
        tk.Label(row2, text="Honey file triggers:", font=("Courier New", 11),
                 fg="#8b949e", bg="#0d1117").pack(side="left")
        tk.Label(row2, textvariable=self._file_hits_var,
                 font=("Courier New", 13, "bold"), fg="#f85149", bg="#0d1117").pack(side="left", padx=6)

    def _refresh_file_preview(self):
        try:
            with open(honey_file_path) as fh:
                content = fh.read()
        except Exception:
            content = "(file not found)"
        self._file_preview.config(state="normal")
        self._file_preview.delete("1.0", "end")
        self._file_preview.insert("end", content)
        self._file_preview.config(state="disabled")

    def _simulate_file_access(self):
        add_alert("Honey File", f"READ access detected on bait file '{honey_file_path}'",
                  severity="HIGH")
        self._file_hits_var.set(self._file_hits_var.get() + 1)

    def _simulate_file_modify(self):
        try:
            with open(honey_file_path, "a") as fh:
                fh.write(f"\n[INTRUDER MODIFICATION at {datetime.datetime.now()}]\n")
        except Exception:
            pass
        add_alert("Honey File",
                  f"WRITE/MODIFY detected on bait file '{honey_file_path}' – possible data exfiltration!",
                  severity="CRITICAL")
        self._file_hits_var.set(self._file_hits_var.get() + 1)
        self._refresh_file_preview()

    # ── TAB 4: DUMMY API ──────────────────────
    def _build_api_tab(self):
        f = self._tab_api
        tk.Label(f, text="Dummy API Endpoint Monitor",
                 font=("Courier New", 13, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(pady=(18, 4), anchor="w", padx=20)

        info = tk.Frame(f, bg="#161b22", highlightthickness=1, highlightbackground="#30363d")
        info.pack(fill="x", padx=20, pady=8, ipady=8)
        tk.Label(info, text=f"Listening on:  http://127.0.0.1:{dummy_api_port}/",
                 font=("Courier New", 10), fg="#c9d1d9", bg="#161b22").pack(anchor="w", padx=12, pady=4)
        tk.Label(info, text="Any HTTP request to this port is treated as suspicious.",
                 font=("Courier New", 10), fg="#8b949e", bg="#161b22").pack(anchor="w", padx=12)

        btn_row = tk.Frame(f, bg="#0d1117")
        btn_row.pack(pady=12)
        tk.Button(btn_row, text=" 🧪 Simulate API Probe ",
                  font=("Courier New", 10, "bold"),
                  bg="#1f6feb", fg="white", relief="flat", cursor="hand2",
                  command=self._simulate_api_probe).pack(side="left", padx=6)

        self._api_hits_var = tk.IntVar(value=0)
        row2 = tk.Frame(f, bg="#0d1117")
        row2.pack(pady=4)
        tk.Label(row2, text="API trap hits:", font=("Courier New", 11),
                 fg="#8b949e", bg="#0d1117").pack(side="left")
        tk.Label(row2, textvariable=self._api_hits_var,
                 font=("Courier New", 13, "bold"), fg="#f85149", bg="#0d1117").pack(side="left", padx=6)

        tk.Label(f, text=f"Test in terminal:  curl http://127.0.0.1:{dummy_api_port}/admin",
                 font=("Courier New", 10, "italic"), fg="#8b949e", bg="#0d1117").pack(pady=6)

    def _simulate_api_probe(self):
        def _probe():
            try:
                import urllib.request
                paths = ["/admin", "/api/v1/users", "/config", "/secret", "/health"]
                path = random.choice(paths)
                urllib.request.urlopen(f"http://127.0.0.1:{dummy_api_port}{path}", timeout=2)
            except Exception:
                pass
            self.after(0, lambda: self._api_hits_var.set(self._api_hits_var.get() + 1))
        threading.Thread(target=_probe, daemon=True).start()

    # ── TAB 5: THREAT INTELLIGENCE ────────────
    def _build_intel_tab(self):
        f = self._tab_intel
        top = tk.Frame(f, bg="#0d1117")
        top.pack(fill="x", padx=14, pady=(12, 4))
        tk.Label(top, text="Per-IP Threat Intelligence",
                 font=("Courier New", 13, "bold"),
                 fg="#58a6ff", bg="#0d1117").pack(side="left")

        # Thresholds legend
        legend = tk.Frame(f, bg="#161b22", highlightthickness=1, highlightbackground="#30363d")
        legend.pack(fill="x", padx=14, pady=(0, 8), ipady=6)
        items = [
            (f"≥{ATTEMPT_WARN_THRESHOLD} hits", "#e07020", "Brute-force WARNING"),
            (f"≥{ATTEMPT_CRITICAL_THRESHOLD} hits", "#cc00cc", "Auto-BLOCK + CRITICAL"),
            ("🔁 tag", "#58a6ff", "Repeat attacker detected"),
            ("🚫 BLOCKED", "#f85149", "IP flagged & blocked"),
        ]
        for tag, col, desc in items:
            row = tk.Frame(legend, bg="#161b22")
            row.pack(side="left", padx=16)
            tk.Label(row, text=tag, font=("Courier New", 9, "bold"),
                     fg=col, bg="#161b22").pack(side="left")
            tk.Label(row, text=f" = {desc}", font=("Courier New", 9),
                     fg="#8b949e", bg="#161b22").pack(side="left")

        # IP table
        cols = ("IP Address", "Hits", "Status", "Sources", "First Seen", "Last Seen")
        self._ip_tree = ttk.Treeview(f, columns=cols, show="headings", height=18)
        widths = [130, 50, 90, 260, 160, 160]
        for col, w in zip(cols, widths):
            self._ip_tree.heading(col, text=col)
            self._ip_tree.column(col, width=w, anchor="w")
        self._ip_tree.tag_configure("BLOCKED", foreground="#f85149")
        self._ip_tree.tag_configure("WARN",    foreground="#e07020")
        self._ip_tree.tag_configure("NORMAL",  foreground="#c9d1d9")

        isb = ttk.Scrollbar(f, orient="vertical", command=self._ip_tree.yview)
        self._ip_tree.configure(yscrollcommand=isb.set)
        self._ip_tree.pack(side="left", fill="both", expand=True, padx=(14, 0), pady=(0, 10))
        isb.pack(side="left", fill="y", pady=(0, 10))

        self._ip_tree_snapshot = {}   # ip → count, to detect changes

    def _refresh_intel(self):
        summary = get_ip_summary()
        changed = False
        for ip, rec in summary:
            prev = self._ip_tree_snapshot.get(ip, {})
            if prev.get("count") != rec["count"] or prev.get("blocked") != rec["blocked"]:
                changed = True
                break
        if changed:
            self._ip_tree.delete(*self._ip_tree.get_children())
            for ip, rec in summary:
                status = "🚫 BLOCKED" if rec["blocked"] else ("⚠ WARNED" if rec["count"] >= ATTEMPT_WARN_THRESHOLD else "👁 WATCHING")
                tag    = "BLOCKED" if rec["blocked"] else ("WARN" if rec["count"] >= ATTEMPT_WARN_THRESHOLD else "NORMAL")
                self._ip_tree.insert("", "end",
                                     values=(ip, rec["count"], status,
                                             rec["sources"], rec["first_seen"], rec["last_seen"]),
                                     tags=(tag,))
                self._ip_tree_snapshot[ip] = {"count": rec["count"], "blocked": rec["blocked"]}
        self.after(1500, self._refresh_intel)



    # ── BACKGROUND TASKS ──────────────────────
    def _start_background_tasks(self):
        # Start dummy API server
        global api_server_thread
        api_server_thread = threading.Thread(target=start_dummy_api, daemon=True)
        api_server_thread.start()

        # Create honey file
        create_honey_file()

        # File modification watcher thread
        threading.Thread(target=self._watch_honey_file, daemon=True).start()

    def _watch_honey_file(self):
        while True:
            time.sleep(3)
            current = get_honey_file_mtime()
            if current and self._honey_mtime and current != self._honey_mtime:
                self._honey_mtime = current
                add_alert("Honey File",
                          f"File system modification detected on '{honey_file_path}'",
                          severity="CRITICAL")
            elif current:
                self._honey_mtime = current

    # ── UI REFRESH LOOP ───────────────────────
    def _refresh_alerts(self):
        with alert_lock:
            new_count = len(alerts)

        if new_count > self._known_alert_count:
            # Insert only new rows
            with alert_lock:
                new_entries = alerts[self._known_alert_count:]
            for e in new_entries:
                sev = e.get("severity", "LOW")
                self._tree.insert("", "end",
                                  values=(e["time"], e["source"], sev,
                                          e.get("ip", "–"), e["detail"]),
                                  tags=(sev,))
            # Auto-scroll to bottom
            children = self._tree.get_children()
            if children:
                self._tree.see(children[-1])
            self._known_alert_count = new_count

            # Update status bar
            last = alerts[-1]
            self._bar_lbl.config(
                text=f"[{last['time']}]  {last['severity']} – {last['source']}: {last['detail'][:80]}"
            )

        # Schedule next refresh
        self.after(1000, self._refresh_alerts)

    def on_close(self):
        global api_server_obj
        if api_server_obj:
            try:
                api_server_obj.shutdown()
            except Exception:
                pass
        self.destroy()


# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app = DeceptionSecurityApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()