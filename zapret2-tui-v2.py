#!/usr/bin/env python3
"""
zapret2-tui v2 — консольный интерфейс управления zapret2
с AI-подбором стратегий обхода DPI.

Требует: Python 3.6+, curses (stdlib)
Ключи API хранятся в файле .env (никогда не в коде и не на GitHub).
Поддерживаемые AI провайдеры: Claude (Anthropic), ChatGPT (OpenAI).
"""

# ──────────────────────────────────────────────────────────────────────────────
#  IMPORTS
# ──────────────────────────────────────────────────────────────────────────────
import curses
import os, sys, json, shlex, textwrap, re, time, threading, subprocess
import urllib.request, urllib.parse, urllib.error
from typing import Optional, List, Dict, Tuple, Callable

# Модули проекта
from zapret2_config import (
    load_env_file, load_user_config, save_user_config,
    get_api_key, get_model, get_active_provider,
    save_api_key_to_env, save_provider_to_env,
    mask_key, check_env_safety, AI_PROVIDERS, ENV_FILE,
)
from zapret2_ai import StrategyFinder, test_api_key, guess_service, normalize_domain

# ──────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────────────────────────────────────

CONFIG_FILE = os.path.expanduser("~/.zapret2-tui.json")

DEFAULT_CONFIG = {
    "zapret_dir":  "/opt/zapret2",
    "binary":      "nfqws2",
    "lua_lib":     "lua/zapret-lib.lua",
    "lua_antidpi": "lua/zapret-antidpi.lua",
    "qnum":        "200",
    "profiles":    [],
    "ai_results":  [],
    "ai_provider": "",   # claude | openai | "" (автовыбор из .env)
    # КЛЮЧИ НЕ ХРАНЯТСЯ ЗДЕСЬ — только в .env файле
}

# ──────────────────────────────────────────────────────────────────────────────
#  STRATEGY TEMPLATES
# ──────────────────────────────────────────────────────────────────────────────

STRATEGY_TEMPLATES = {
    "HTTPS TLS (базовый)": {
        "desc": "fake+multidisorder, MD5 fooling",
        "filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
        "desync": ["fake:blob=fake_default_tls:tcp_md5:repeats=6",
                   "multidisorder:pos=midsld"],
    },
    "HTTPS TLS (autottl)": {
        "desc": "fake+fakedsplit с автоматическим TTL",
        "filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
        "desync": ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5",
                   "fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5"],
    },
    "HTTP (базовый)": {
        "desc": "fake+fakedsplit для HTTP",
        "filter_tcp": "80", "filter_l7": "http", "out_range": "-d10",
        "desync": ["fake:blob=fake_default_http:ip_autottl=-2,3-20:tcp_md5",
                   "fakedsplit:ip_autottl=-2,3-20:tcp_md5"],
    },
    "QUIC / YouTube UDP": {
        "desc": "QUIC fake repeats",
        "filter_udp": "443", "filter_l7": "quic",
        "desync": ["fake:blob=fake_default_quic:repeats=11"],
    },
    "YouTube HTTPS (sni=google)": {
        "desc": "SNI подмена на www.google.com",
        "filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
        "desync": ["fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com",
                   "multidisorder:pos=1,midsld"],
    },
    "wssize + syndata": {
        "desc": "Уменьшение TCP window size",
        "filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
        "desync": ["wssize:wsize=1:scale=6", "syndata", "multisplit:pos=midsld"],
    },
    "Discord / WireGuard / STUN": {
        "desc": "UDP обфускация для Discord/WG/STUN",
        "filter_l7": "wireguard,stun,discord",
        "desync": ["fake:blob=0x00000000000000000000000000000000:repeats=2"],
    },
    "Полный комплект (HTTP+HTTPS+QUIC)": {
        "desc": "Три протокола одновременно",
        "multiprofile": True,
        "profiles": [
            {"filter_tcp": "80",  "filter_l7": "http",  "out_range": "-d10",
             "desync": ["fake:blob=fake_default_http:ip_autottl=-2,3-20:tcp_md5",
                        "fakedsplit:ip_autottl=-2,3-20:tcp_md5"]},
            {"filter_tcp": "443", "filter_l7": "tls",   "out_range": "-d10",
             "desync": ["fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6",
                        "multidisorder:pos=midsld"]},
            {"filter_udp": "443", "filter_l7": "quic",
             "desync": ["fake:blob=fake_default_quic:repeats=11"]},
        ],
    },
}

# Матрица встроенных кандидатов для AI-подбора
BUILTIN_CANDIDATES = [
    ("443", "tls",  "-d10",  ["fake:blob=fake_default_tls:tcp_md5:repeats=6", "multidisorder:pos=midsld"]),
    ("443", "tls",  "-d10",  ["fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6", "multidisorder:pos=midsld"]),
    ("443", "tls",  "-d10",  ["fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com", "multidisorder:pos=1,midsld"]),
    ("443", "tls",  "-d10",  ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5", "fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5"]),
    ("443", "tls",  "-d10",  ["fake:blob=fake_default_tls:tcp_md5:repeats=6:tls_mod=rnd,rndsni,dupsid", "multisplit:pos=1:seqovl=5"]),
    ("443", "tls",  "-d10",  ["wssize:wsize=1:scale=6", "syndata", "multisplit:pos=midsld"]),
    ("443", "tls",  "-d10",  ["fake:blob=fake_default_tls:tcp_flags_unset=ack:tls_mod=rnd,rndsni,dupsid"]),
    ("443", "tls",  "-d10",  ["fakedsplit:ip_autottl=-1,3-20:tcp_md5"]),
    ("443", "tls",  "-d10",  ["multisplit:pos=1,midsld"]),
    ("80,443", "tls,http", "-d10", ["fake:blob=fake_default_tls:tcp_md5", "multidisorder:pos=midsld"]),
]

# ──────────────────────────────────────────────────────────────────────────────
#  UTILS
# ──────────────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            cfg = json.load(open(CONFIG_FILE))
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict):
    # Никогда не сохраняем ключи в конфиг — только в .env
    safe = {k: v for k, v in cfg.items()
            if k not in ("anthropic_key", "openai_key")}
    json.dump(safe, open(CONFIG_FILE, "w"), indent=2, ensure_ascii=False)

def find_binary(cfg: dict) -> Optional[str]:
    import shutil
    for c in [
        os.path.join(cfg["zapret_dir"], cfg["binary"]),
        os.path.join(cfg["zapret_dir"], "binaries", cfg["binary"]),
        cfg["binary"],
    ]:
        if os.path.isfile(c):
            return c
    return shutil.which(cfg["binary"])

def build_cmdline(cfg: dict, profile: dict, extra: str = "") -> List[str]:
    binary = find_binary(cfg) or cfg["binary"]
    zdir   = cfg["zapret_dir"]
    lib    = os.path.join(zdir, cfg["lua_lib"])
    adpi   = os.path.join(zdir, cfg["lua_antidpi"])
    cmd = [binary, f"--qnum={cfg['qnum']}",
           f"--lua-init=@{lib}", f"--lua-init=@{adpi}"]
    for li in profile.get("lua_init", []):  cmd.append(f"--lua-init={li}")
    for b  in profile.get("blobs",    []):  cmd.append(f"--blob={b}")

    def block(p, last):
        if p.get("filter_tcp"):   cmd.append(f"--filter-tcp={p['filter_tcp']}")
        if p.get("filter_udp"):   cmd.append(f"--filter-udp={p['filter_udp']}")
        if p.get("filter_l7"):    cmd.append(f"--filter-l7={p['filter_l7']}")
        if p.get("hostlist"):
            hl = p["hostlist"] if os.path.isabs(p["hostlist"]) else os.path.join(zdir, p["hostlist"])
            cmd.append(f"--hostlist={hl}")
        if p.get("out_range"):    cmd.append(f"--out-range={p['out_range']}")
        if p.get("in_range"):     cmd.append(f"--in-range={p['in_range']}")
        for ds in p.get("desync", []): cmd.append(f"--lua-desync={ds}")
        if not last: cmd.append("--new")

    if profile.get("multiprofile"):
        subs = profile["profiles"]
        for i, p in enumerate(subs): block(p, i == len(subs)-1)
    else:
        block(profile, True)
    if extra: cmd += shlex.split(extra)
    return cmd

# ──────────────────────────────────────────────────────────────────────────────
#  CONNECTIVITY CHECK (используется в TUI для быстрой проверки)
# ──────────────────────────────────────────────────────────────────────────────

def check_url(domain: str, timeout=8) -> Tuple[bool,str]:
    url = f"https://{domain}" if not domain.startswith("http") else domain
    try:
        r = subprocess.run(
            ["curl","-s","-o","/dev/null","-w","%{http_code}",
             "--max-time",str(timeout),"--connect-timeout","5","-L","--insecure",url],
            capture_output=True, text=True, timeout=timeout+3)
        code = r.stdout.strip()
        ok = code.isdigit() and 200 <= int(code) < 400
        return ok, f"HTTP {code}"
    except FileNotFoundError:
        try:
            req = urllib.request.Request(url, headers={"User-Agent":"curl/7.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return True, f"HTTP {resp.status}"
        except Exception as e:
            return False, str(e)
    except Exception as e:
        return False, str(e)

# ──────────────────────────────────────────────────────────────────────────────
#  CURSES COLORS
# ──────────────────────────────────────────────────────────────────────────────

C_TITLE=1; C_MENU=2; C_SEL=3; C_STATUS=4; C_BORDER=5
C_KEY=6;   C_WARN=7; C_OK=8;  C_DIM=9;    C_AI=10

def init_colors():
    curses.start_color(); curses.use_default_colors()
    curses.init_pair(C_TITLE,  curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C_MENU,   curses.COLOR_WHITE,   -1)
    curses.init_pair(C_SEL,    curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(C_STATUS, curses.COLOR_BLACK,   curses.COLOR_YELLOW)
    curses.init_pair(C_BORDER, curses.COLOR_CYAN,    -1)
    curses.init_pair(C_KEY,    curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_WARN,   curses.COLOR_RED,     -1)
    curses.init_pair(C_OK,     curses.COLOR_GREEN,   -1)
    curses.init_pair(C_DIM,    curses.COLOR_WHITE,   -1)
    curses.init_pair(C_AI,     curses.COLOR_MAGENTA, -1)

# ──────────────────────────────────────────────────────────────────────────────
#  MAIN TUI CLASS
# ──────────────────────────────────────────────────────────────────────────────

class ZapretTUI:
    def __init__(self, scr):
        self.scr = scr
        self.cfg = load_config()
        self.proc = None
        self.log_lines = []
        self.status_msg = ""
        self.ai_finder = None
        self.ai_progress = ("Ожидание…", 0, 100)
        self.ai_new_results = []
        self._ai_lock = threading.Lock()
        self._ai_done = False
        self._ai_success = False
        # Features init
        from zapret2_features import (
            load_features, save_features,
            HostlistManager, DomainMonitor,
            Watchdog, AutostartManager, StrategyUpdater,
        )
        self._save_features = save_features
        self.feat      = load_features()
        self.hlm       = HostlistManager(self.cfg["zapret_dir"])
        self.monitor   = DomainMonitor(self.feat.get("monitor_interval", 30))
        self.watchdog  = Watchdog(self.cfg, self.feat,
                                  log_cb=self.add_log,
                                  switch_cb=self._watchdog_switch,
                                  get_proc_cb=lambda: self.proc)
        self.autostart = AutostartManager(self.cfg, self.feat, self.add_log)
        self.updater   = StrategyUpdater(self.cfg, self.feat,
                                         log_cb=self.add_log,
                                         new_profile_cb=self._on_new_profile)
        # ВАЖНО: _setup() ДО _start_bg() — сначала инициализируем curses
        self._setup()
        self._start_bg()
        self.main_loop()

    def _start_bg(self):
        monitor_hl = self.hlm.get_monitor_hostlist()
        domains = self.hlm.read_domains(monitor_hl)
        if domains:
            self.monitor.set_domains(domains)
            self.monitor.start()
        if self.feat.get("watchdog_enabled"):
            self.watchdog.start()
        if self.feat.get("autoupdate_enabled"):
            self.updater.start()

    def _watchdog_switch(self):
        profiles = self.cfg.get("profiles", [])
        if not profiles:
            self.add_log("[WD] Нет профилей для переключения"); return
        cur_idx = next((i for i,p in enumerate(profiles)
                        if p.get("name") == self.status_msg), -1)
        nxt = profiles[(cur_idx + 1) % len(profiles)]
        self.add_log(f"[WD] Переключаюсь на: {nxt.get('name')}")
        self.stop_zapret()
        time.sleep(1)
        self.start_zapret(nxt)

    def _on_new_profile(self, profile):
        self.cfg.setdefault("profiles", []).append(profile)
        save_config(self.cfg)

    def _setup(self):
        curses.curs_set(0); self.scr.keypad(True); init_colors()

    # ── Лог ──────────────────────────────────────────────────────────────────
    def add_log(self, line: str):
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S ")
        self.log_lines.append(ts + line)
        if len(self.log_lines) > 600:
            self.log_lines = self.log_lines[-600:]

    # ── Отрисовка утилиты ────────────────────────────────────────────────────
    def _center(self, win, row, text, attr=0):
        h, w = win.getmaxyx()
        x = max(0, (w - len(text)) // 2)
        try: win.addstr(row, x, text[:w-2], attr)
        except curses.error: pass

    def border_box(self, win, title=""):
        win.box()
        if title:
            w = win.getmaxyx()[1]
            t = f" {title} "
            try: win.addstr(0, max(2,(w-len(t))//2), t,
                            curses.color_pair(C_BORDER)|curses.A_BOLD)
            except curses.error: pass

    def draw_title(self):
        h, w = self.scr.getmaxyx()
        t = " zapret2-tui v2  [AI стратегии] "
        try: self.scr.addstr(0, 0, t.center(w),
                             curses.color_pair(C_TITLE)|curses.A_BOLD)
        except curses.error: pass

    def draw_statusbar(self):
        h, w = self.scr.getmaxyx()
        running = self.proc and self.proc.poll() is None
        if running:
            s = f" ▶ ЗАПУЩЕН PID={self.proc.pid}  {self.status_msg}"
            a = curses.color_pair(C_OK)|curses.A_BOLD
        elif self.ai_finder and not self._ai_done:
            msg, cur, tot = self.ai_progress
            s = f" 🤖 AI: {msg[:50]}  [{cur}/{tot}]"
            a = curses.color_pair(C_AI)|curses.A_BOLD
        else:
            s = f" ■ СТОП  {self.status_msg}"
            a = curses.color_pair(C_STATUS)
        try: self.scr.addstr(h-1, 0, s[:w-1].ljust(w-1), a)
        except curses.error: pass

    # ── Диалоги ──────────────────────────────────────────────────────────────
    def msgbox(self, msg, title="Сообщение"):
        h, w = self.scr.getmaxyx()
        lines = []
        for ln in msg.split("\n"):
            lines += textwrap.wrap(ln, w-8) or [""]
        bh = min(len(lines)+5, h-4); bw = min(max(len(l) for l in lines)+6, w-4)
        y=(h-bh)//2; x=(w-bw)//2
        win = curses.newwin(bh, bw, y, x)
        win.bkgd(' ', curses.color_pair(C_MENU)); self.border_box(win, title)
        for i, ln in enumerate(lines[:bh-4]):
            try: win.addstr(i+2, 3, ln[:bw-6])
            except curses.error: pass
        try: win.addstr(bh-1, (bw-10)//2, " [ OK ] ", curses.color_pair(C_KEY))
        except curses.error: pass
        win.refresh()
        while win.getch() not in (10,13,27,ord('q')): pass
        del win; self.scr.touchwin(); self.scr.refresh()

    def inputbox(self, prompt, default="", title="Ввод") -> Optional[str]:
        h, w = self.scr.getmaxyx()
        bw = min(max(len(prompt)+8, 55), w-4); bh = 7
        y=(h-bh)//2; x=(w-bw)//2
        win = curses.newwin(bh, bw, y, x)
        win.bkgd(' ', curses.color_pair(C_MENU)); self.border_box(win, title)
        try: win.addstr(2, 3, prompt[:bw-6])
        except curses.error: pass
        ew = curses.newwin(1, bw-6, y+4, x+3)
        ew.bkgd(' ', curses.color_pair(C_SEL))
        curses.curs_set(1)
        buf = list(default); pos = len(buf)
        while True:
            ew.clear()
            disp = "".join(buf)
            try: ew.addstr(0, 0, disp[:bw-8]); ew.move(0, min(pos, bw-9))
            except curses.error: pass
            ew.refresh(); k = win.getch()
            if k in (10,13):
                curses.curs_set(0); del ew; del win
                self.scr.touchwin(); self.scr.refresh()
                return "".join(buf)
            elif k==27:
                curses.curs_set(0); del ew; del win
                self.scr.touchwin(); self.scr.refresh(); return None
            elif k in (curses.KEY_BACKSPACE, 127, 8):
                if pos > 0: buf.pop(pos-1); pos-=1
            elif k==curses.KEY_DC:
                if pos < len(buf): buf.pop(pos)
            elif k==curses.KEY_LEFT:  pos=max(0,pos-1)
            elif k==curses.KEY_RIGHT: pos=min(len(buf),pos+1)
            elif 32<=k<256: buf.insert(pos,chr(k)); pos+=1

    def confirm(self, q, title="Подтверждение") -> bool:
        h, w = self.scr.getmaxyx()
        lines = textwrap.wrap(q, w-10) or [q]
        bh = len(lines)+6; bw = min(max(len(l) for l in lines)+8, w-4)
        y=(h-bh)//2; x=(w-bw)//2
        win = curses.newwin(bh, bw, y, x)
        win.bkgd(' ', curses.color_pair(C_MENU)); self.border_box(win, title)
        for i, ln in enumerate(lines):
            try: win.addstr(i+2, 3, ln[:bw-6])
            except curses.error: pass
        sel = 0
        while True:
            for i,(lbl,col) in enumerate([(" ДА ", C_OK),(" НЕТ ", C_WARN)]):
                a = (curses.color_pair(col)|curses.A_BOLD) if i==sel else curses.color_pair(C_DIM)
                try: win.addstr(bh-2, 4+i*10, lbl, a)
                except curses.error: pass
            win.refresh(); k = win.getch()
            if k in (curses.KEY_LEFT, curses.KEY_RIGHT, 9): sel=1-sel
            elif k in (10,13):
                del win; self.scr.touchwin(); self.scr.refresh(); return sel==0
            elif k==27:
                del win; self.scr.touchwin(); self.scr.refresh(); return False

    def menu(self, items, title="", y_off=2, x_off=2, height=None, width=None) -> int:
        h, w = self.scr.getmaxyx()
        mw = min((width or max((len(i) for i in items), default=10)+4), w-x_off-2)
        mh = min((height or len(items)+2), h-y_off-2)
        win = curses.newwin(mh, mw, y_off, x_off)
        win.bkgd(' ', curses.color_pair(C_MENU)); self.border_box(win, title)
        sel=0; scroll=0; vis=mh-2
        while True:
            for i in range(vis):
                idx=i+scroll
                if idx>=len(items): break
                lbl = items[idx][:mw-4]
                a = (curses.color_pair(C_SEL)|curses.A_BOLD) if idx==sel else curses.color_pair(C_MENU)
                try: win.addstr(i+1, 2, f" {lbl:<{mw-4}} ", a)
                except curses.error: pass
            win.refresh(); k=win.getch()
            if k==curses.KEY_UP:
                sel=max(0,sel-1)
                if sel<scroll: scroll=sel
            elif k==curses.KEY_DOWN:
                sel=min(len(items)-1,sel+1)
                if sel>=scroll+vis: scroll=sel-vis+1
            elif k in (10,13):
                del win; self.scr.touchwin(); self.scr.refresh(); return sel
            elif k==27:
                del win; self.scr.touchwin(); self.scr.refresh(); return -1
        del win; self.scr.touchwin(); self.scr.refresh(); return -1

    # ── Лог экран ────────────────────────────────────────────────────────────
    def show_log(self):
        h, w = self.scr.getmaxyx()
        bh=h-4; bw=w-4
        win=curses.newwin(bh,bw,2,2); win.bkgd(' ',curses.color_pair(C_MENU))
        scroll=max(0,len(self.log_lines)-(bh-2))
        while True:
            win.clear(); self.border_box(win,"Лог  (↑↓  PgUp/PgDn  End  q=выход)")
            vis=bh-2
            for i in range(vis):
                idx=scroll+i
                if idx>=len(self.log_lines): break
                ln=self.log_lines[idx][:bw-4]
                if "[AI]" in ln: a=curses.color_pair(C_AI)
                elif "ОШИБК" in ln.upper() or "ERROR" in ln.upper(): a=curses.color_pair(C_WARN)
                elif "УСПЕХ" in ln or "✓" in ln: a=curses.color_pair(C_OK)
                else: a=curses.color_pair(C_DIM)
                try: win.addstr(i+1,2,ln,a)
                except curses.error: pass
            win.refresh(); k=win.getch()
            if k in (27,ord('q')): break
            elif k==curses.KEY_UP:    scroll=max(0,scroll-1)
            elif k==curses.KEY_DOWN:  scroll=min(max(0,len(self.log_lines)-vis),scroll+1)
            elif k==curses.KEY_PPAGE: scroll=max(0,scroll-vis)
            elif k==curses.KEY_NPAGE: scroll=min(max(0,len(self.log_lines)-vis),scroll+vis)
            elif k==curses.KEY_END:   scroll=max(0,len(self.log_lines)-vis)
            elif k==curses.KEY_HOME:  scroll=0
        del win; self.scr.touchwin(); self.scr.refresh()

    # ── Запуск/стоп zapret ────────────────────────────────────────────────────
    def start_zapret(self, profile, debug=False, extra=""):
        if self.proc and self.proc.poll() is None:
            self.msgbox("zapret2 уже запущен!\nСначала остановите текущий процесс.","Ошибка"); return
        cmd = build_cmdline(self.cfg, profile, extra)
        if debug: cmd.append("--debug")
        self.add_log("Запуск: " + " ".join(shlex.quote(a) for a in cmd[:8]) + "…")
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
            self.add_log(f"Запущен PID={self.proc.pid}")
            self.status_msg = profile.get("name","(без имени)")
        except PermissionError:
            self.msgbox("Нет прав root/sudo.","Ошибка")
        except FileNotFoundError:
            self.msgbox(f"Бинарник не найден:\n{cmd[0]}","Ошибка")
        except Exception as e:
            self.msgbox(str(e),"Ошибка")

    def stop_zapret(self):
        if not self.proc or self.proc.poll() is not None:
            self.status_msg=""; return
        try:
            self.proc.terminate()
            try: self.proc.wait(3)
            except subprocess.TimeoutExpired: self.proc.kill()
            self.add_log(f"Остановлен PID={self.proc.pid}")
        except Exception as e:
            self.add_log(f"Ошибка стопа: {e}")
        self.proc=None; self.status_msg=""

    def poll_proc(self):
        if not self.proc: return
        if self.proc.poll() is not None:
            try:
                out,_=self.proc.communicate(timeout=0.05)
                if out:
                    for ln in out.splitlines(): self.add_log(ln)
            except Exception: pass
            self.add_log(f"Процесс завершился (код {self.proc.returncode})")
            self.proc=None; return
        try:
            import select
            rdy,_,_=select.select([self.proc.stdout],[],[],0)
            if rdy:
                ln=self.proc.stdout.readline()
                if ln: self.add_log(ln.rstrip())
        except Exception: pass

    # ── AI результаты (thread-safe) ───────────────────────────────────────────
    def _ai_found_cb(self, profile: dict):
        with self._ai_lock:
            self.ai_new_results.append(profile)
        self.add_log(f"[AI] ✓ Найдена стратегия: {profile.get('name','?')[:50]}")

    def _ai_progress_cb(self, msg: str, cur: int, tot: int):
        self.ai_progress = (msg, cur, tot)

    def _ai_done_cb(self, success: bool):
        self._ai_done = True
        self._ai_success = success
        with self._ai_lock:
            results = list(self.ai_new_results)
        if results:
            for p in results:
                if p not in self.cfg.get("profiles",[]):
                    self.cfg.setdefault("profiles",[]).append(p)
            save_config(self.cfg)
            self.add_log(f"[AI] Сохранено {len(results)} профилей")
        self.add_log(f"[AI] Подбор завершён: {'УСПЕХ' if success else 'НЕ НАЙДЕНО'}")

    # ── AI подбор стратегии ───────────────────────────────────────────────────
    def ai_strategy_menu(self):
        # Проверяем наличие хоть какого-то ключа
        provider = get_active_provider(self.cfg)
        has_key  = bool(get_api_key(provider, self.cfg))

        if not has_key:
            # Предлагаем настроить провайдера
            choice = self.menu(
                ["🤖 Настроить Claude (Anthropic)",
                 "💬 Настроить ChatGPT (OpenAI)",
                 "⚡ Продолжить без AI (только встроенные стратегии)",
                 "← Назад"],
                "AI ключ не настроен", y_off=4, x_off=4
            )
            if choice == 3 or choice == -1:
                return
            elif choice == 0:
                self._setup_ai_provider("claude")
                provider = "claude"
            elif choice == 1:
                self._setup_ai_provider("openai")
                provider = "openai"
            # choice == 2 — продолжаем без ключа

        domain_raw = self.inputbox(
            "Сайт/домен/IP для разблокировки:",
            "instagram.com", "AI Подбор стратегии"
        )
        if not domain_raw:
            return

        domain = normalize_domain(domain_raw)
        svc = guess_service(domain)

        # Выбор: только поиск или + запуск тестов
        h, w = self.scr.getmaxyx()
        action = self.menu(
            [f"🤖 Полный подбор: поиск + тест стратегий для {svc}",
             "🔍 Только поиск решений в интернете (без тестов)",
             "🎛  Миксовать существующие профили",
             "← Назад"],
            "Режим AI подбора", y_off=4, x_off=4, width=min(w-8,65)
        )

        if action == 3 or action == -1:
            return
        elif action == 2:
            self._mix_profiles_menu()
            return
        elif action == 1:
            self._ai_search_only(domain, svc)
            return

        # Полный подбор
        if self.ai_finder and not self._ai_done:
            if not self.confirm("AI подбор уже запущен. Остановить и начать новый?"):
                return
            self.ai_finder.stop()

        self._ai_done = False
        self._ai_success = False
        with self._ai_lock:
            self.ai_new_results.clear()

        self.ai_finder = StrategyFinder(
            domain, self.cfg,
            log_cb      = self.add_log,
            progress_cb = self._ai_progress_cb,
            found_cb    = self._ai_found_cb,
            done_cb     = self._ai_done_cb,
        )
        self.ai_finder.start()
        self.add_log(f"[AI] Запущен подбор для {domain}")

        # Показываем экран ожидания
        self._ai_wait_screen(domain, svc)

    def _ai_wait_screen(self, domain: str, svc: str):
        """Интерактивный экран прогресса AI подбора."""
        h, w = self.scr.getmaxyx()
        while True:
            self.poll_proc()
            # Проверяем новые результаты
            with self._ai_lock:
                new = list(self.ai_new_results)

            # Рисуем экран
            self.scr.clear()
            self.draw_title()
            bh=h-4; bw=w-4
            win=curses.newwin(bh,bw,2,2); win.bkgd(' ',curses.color_pair(C_MENU))
            self.border_box(win, f"AI Подбор: {svc} ({domain})")

            # Статус
            msg, cur, tot = self.ai_progress
            pct = int(cur*100/tot) if tot>0 else 0
            bar_w = bw-20
            filled = int(bar_w * pct / 100)
            bar = "█"*filled + "░"*(bar_w-filled)
            try:
                win.addstr(2, 3, f"Прогресс: {pct:3d}%  ", curses.color_pair(C_KEY)|curses.A_BOLD)
                win.addstr(2, 18, f"[{bar}]", curses.color_pair(C_AI))
                win.addstr(3, 3, msg[:bw-6], curses.color_pair(C_DIM))
            except curses.error: pass

            # Найденные стратегии
            try: win.addstr(5, 3, "Найденные стратегии:", curses.color_pair(C_KEY)|curses.A_BOLD)
            except curses.error: pass
            if new:
                for i, p in enumerate(new[:bh-14]):
                    name = p.get("name","?")[:bw-10]
                    src  = p.get("source","?")
                    icon = "⭐" if "mixed" not in src else "🔀"
                    try: win.addstr(6+i, 3, f"{icon} {name}", curses.color_pair(C_OK))
                    except curses.error: pass
            else:
                try: win.addstr(6, 3, "  (поиск идёт…)", curses.color_pair(C_DIM))
                except curses.error: pass

            # Последние строки лога
            log_row = max(8, 6+len(new)+2)
            try: win.addstr(log_row, 3, "Лог:", curses.color_pair(C_KEY))
            except curses.error: pass
            log_vis = bh - log_row - 4
            for i, ln in enumerate(self.log_lines[-log_vis:]):
                if log_row+1+i >= bh-2: break
                if "[AI]" in ln: a=curses.color_pair(C_AI)
                elif "✓" in ln:  a=curses.color_pair(C_OK)
                elif "✗" in ln:  a=curses.color_pair(C_WARN)
                else:            a=curses.color_pair(C_DIM)
                try: win.addstr(log_row+1+i, 3, ln[:bw-6], a)
                except curses.error: pass

            # Кнопки
            try:
                win.addstr(bh-2, 3,
                           " S Стоп AI  L Лог  Enter Применить найденное  Esc Назад ",
                           curses.color_pair(C_KEY))
            except curses.error: pass

            if self._ai_done:
                if self._ai_success and new:
                    try: win.addstr(bh-3, 3, f"✓ УСПЕХ! Найдено {len(new)} стратегий. Enter = применить",
                                    curses.color_pair(C_OK)|curses.A_BOLD)
                    except curses.error: pass
                else:
                    try: win.addstr(bh-3, 3, "✗ Рабочая стратегия не найдена. Esc = назад",
                                    curses.color_pair(C_WARN)|curses.A_BOLD)
                    except curses.error: pass

            win.refresh()
            self.draw_statusbar()
            self.scr.refresh()

            self.scr.timeout(400)
            k = self.scr.getch()

            if k in (27, ord('q')) and self._ai_done:
                del win; self.scr.touchwin(); self.scr.refresh(); return
            elif k == 27 and not self._ai_done:
                if self.confirm("AI подбор ещё идёт. Остановить?"):
                    self.ai_finder.stop()
                    del win; self.scr.touchwin(); self.scr.refresh(); return
            elif k in (10, 13) and new:
                del win; self.scr.touchwin(); self.scr.refresh()
                self._apply_ai_results(new)
                return
            elif k in (ord('s'), ord('S')):
                if self.ai_finder and not self._ai_done:
                    self.ai_finder.stop(); self._ai_done=True
            elif k in (ord('l'), ord('L')):
                del win; self.scr.touchwin(); self.scr.refresh()
                self.show_log(); return
            del win

    def _apply_ai_results(self, results: List[dict]):
        """Предлагает применить/запустить найденные AI стратегии."""
        if not results:
            self.msgbox("Нет результатов для применения."); return

        items = [f"{'🔀' if p.get('source')=='mixed' else '⭐'} {p.get('name','?')[:55]}"
                 for p in results]
        items += ["← Назад"]
        h, w = self.scr.getmaxyx()
        idx = self.menu(items, "Выберите стратегию",
                        y_off=3, x_off=3,
                        height=min(len(items)+2, h-6),
                        width=min(w-6, 68))
        if idx < 0 or idx == len(results):
            return

        profile = results[idx]
        actions = ["▶ Запустить сейчас",
                   "▶ Запустить с --debug",
                   "💾 Сохранить в профили",
                   "🎛  Смешать с другим профилем",
                   "← Назад"]
        act = self.menu(actions, profile.get("name","?")[:40], y_off=5, x_off=5)
        if act == 0:
            self.start_zapret(profile)
        elif act == 1:
            self.start_zapret(profile, debug=True)
        elif act == 2:
            if profile not in self.cfg["profiles"]:
                self.cfg["profiles"].append(profile)
                save_config(self.cfg)
                self.add_log(f"Сохранён: {profile.get('name')}")
                self.msgbox(f"Профиль сохранён:\n{profile.get('name','')}", "Сохранено")
        elif act == 3:
            self._mix_with_other(profile)

    def _ai_search_only(self, domain: str, svc: str):
        """Только поиск без тестирования."""
        provider = get_active_provider(self.cfg)
        has_key  = bool(get_api_key(provider, self.cfg))
        if not has_key:
            self.msgbox("Для поиска нужен API ключ.\n6 → Настройки → AI провайдер", "Нет ключа")
            return

        self.add_log(f"[AI] Поиск решений для {domain}…")
        results = []
        done = threading.Event()

        def _search():
            finder = StrategyFinder(domain, self.cfg,
                                    self.add_log, lambda *a: None,
                                    lambda p: results.append(p), lambda s: done.set())
            candidates = finder.search_internet()
            for c in candidates:
                c["name"] = f"{svc} [web]: {c.get('name','?')}"
                results.append(c)
            done.set()

        t = threading.Thread(target=_search, daemon=True)
        t.start()

        # Ждём с прогресс-спиннером
        h, w = self.scr.getmaxyx()
        spinner = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        si = 0
        while not done.is_set():
            self.scr.clear(); self.draw_title()
            self.scr.addstr(h//2, w//2-20,
                            f" {spinner[si%10]} Ищу в интернете для {domain}… ",
                            curses.color_pair(C_AI)|curses.A_BOLD)
            self.scr.refresh(); time.sleep(0.15); si+=1

        if results:
            self._apply_ai_results(results)
        else:
            self.msgbox(f"Готовых решений для {domain} не найдено.\nПопробуйте полный подбор.", "Результат")

    # ── Миксование профилей ───────────────────────────────────────────────────
    def _mix_profiles_menu(self):
        all_p = self.cfg.get("profiles", [])
        templates = [{**v, "name": k} for k, v in STRATEGY_TEMPLATES.items()]
        pool = all_p + templates

        if len(pool) < 2:
            self.msgbox("Нужно минимум 2 профиля для смешивания."); return

        h, w = self.scr.getmaxyx()
        items = [p.get("name","?")[:55] for p in pool]
        self.msgbox("Выберите первый профиль для микса:", "Микс")
        idx_a = self.menu(items, "Первый профиль",
                          y_off=3, x_off=3,
                          height=min(len(items)+2,h-6), width=min(w-6,62))
        if idx_a < 0: return
        self.msgbox("Выберите второй профиль:", "Микс")
        idx_b = self.menu(items, "Второй профиль",
                          y_off=3, x_off=3,
                          height=min(len(items)+2,h-6), width=min(w-6,62))
        if idx_b < 0 or idx_b == idx_a: return

        a, b = pool[idx_a], pool[idx_b]
        self._mix_with_other(a, b)

    def _mix_with_other(self, profile_a: dict, profile_b: dict = None):
        if profile_b is None:
            all_p = self.cfg.get("profiles",[])
            templates = [{**v,"name":k} for k,v in STRATEGY_TEMPLATES.items()]
            pool = [p for p in all_p+templates if p is not profile_a]
            if not pool: self.msgbox("Нет других профилей для микса."); return
            h,w=self.scr.getmaxyx()
            idx=self.menu([p.get("name","?")[:55] for p in pool],"Второй профиль",
                          y_off=3,x_off=3,height=min(len(pool)+2,h-6),width=min(w-6,62))
            if idx<0: return
            profile_b = pool[idx]

        # Создаём мульти-профиль
        def _to_subprofile(p):
            if p.get("multiprofile"):
                return p.get("profiles",[])
            return [{
                "filter_tcp": p.get("filter_tcp",""),
                "filter_udp": p.get("filter_udp",""),
                "filter_l7":  p.get("filter_l7",""),
                "out_range":  p.get("out_range",""),
                "desync":     p.get("desync",[]),
            }]

        subs_a = _to_subprofile(profile_a)
        subs_b = _to_subprofile(profile_b)
        name = f"Микс: {profile_a.get('name','A')[:20]} + {profile_b.get('name','B')[:20]}"
        mixed = {
            "name": name,
            "source": "mixed",
            "multiprofile": True,
            "profiles": subs_a + subs_b,
        }
        # Показываем предпросмотр
        cmd = build_cmdline(self.cfg, mixed)
        preview = " ".join(shlex.quote(a) for a in cmd[:10]) + "…"
        if self.confirm(f"Создать смешанный профиль:\n{name}\n\nКоманда: {preview[:80]}"):
            self.cfg.setdefault("profiles",[]).append(mixed)
            save_config(self.cfg)
            self.add_log(f"Создан микс: {name}")
            actions = ["▶ Запустить сейчас", "💾 Только сохранить", "← Отмена"]
            act = self.menu(actions, "Готово!", y_off=5, x_off=5)
            if act==0: self.start_zapret(mixed)

    # ── Профили ───────────────────────────────────────────────────────────────
    def profiles_menu(self):
        while True:
            profiles = self.cfg.get("profiles",[])
            items = []
            for p in profiles:
                mp = "⊞" if p.get("multiprofile") else " "
                src = p.get("source","")
                icon = "🤖" if "ai" in src.lower() or "web" in src.lower() else ("🔀" if "mixed" in src else "▸")
                items.append(f"{icon}{mp} {p.get('name','?')[:50]}")
            items += ["  + Новый профиль", "← Назад"]
            h,w=self.scr.getmaxyx()
            idx=self.menu(items,"Профили",y_off=2,x_off=2,
                          height=min(len(items)+2,h-4),width=min(w-4,70))
            if idx==-1 or idx==len(items)-1: break
            elif idx==len(items)-2:
                p=self._edit_profile()
                if p: self.cfg["profiles"].append(p); save_config(self.cfg)
            elif idx<len(profiles):
                p=profiles[idx]
                acts=["▶ Запустить","▶ Запустить с --debug",
                      "✏  Редактировать","🔀 Смешать с другим",
                      "⧉  Дублировать","✗  Удалить","← Назад"]
                act=self.menu(acts,p.get("name","")[:40],y_off=4,x_off=4)
                if act==0: self.start_zapret(p)
                elif act==1: self.start_zapret(p,debug=True)
                elif act==2:
                    ep=self._edit_profile(p)
                    if ep: self.cfg["profiles"][idx]=ep; save_config(self.cfg)
                elif act==3: self._mix_with_other(p)
                elif act==4:
                    import copy; dup=copy.deepcopy(p); dup["name"]+=" (копия)"
                    self.cfg["profiles"].append(dup); save_config(self.cfg)
                elif act==5:
                    if self.confirm(f"Удалить '{p.get('name')}'?"):
                        self.cfg["profiles"].pop(idx); save_config(self.cfg)

    def _edit_profile(self, profile=None) -> Optional[dict]:
        import copy
        if profile is None:
            profile={"name":"Новый профиль","filter_tcp":"443","filter_udp":"",
                     "filter_l7":"tls","hostlist":"","out_range":"-d10",
                     "desync":["fake:blob=fake_default_tls:tcp_md5","multidisorder:pos=midsld"]}
        else:
            profile=copy.deepcopy(profile)

        fields=[("name","Имя профиля"),("filter_tcp","TCP порты"),
                ("filter_udp","UDP порты"),("filter_l7","Протокол L7"),
                ("hostlist","Hostlist файл"),("out_range","Out range"),("in_range","In range")]
        while True:
            self.scr.clear(); self.draw_title()
            h,w=self.scr.getmaxyx()
            bh=len(fields)+12; bw=min(72,w-4)
            y=(h-bh)//2; x=(w-bw)//2
            win=curses.newwin(bh,bw,y,x)
            win.bkgd(' ',curses.color_pair(C_MENU)); self.border_box(win,"Редактор профиля")
            for i,(k,lbl) in enumerate(fields):
                val=str(profile.get(k,""))
                try:
                    win.addstr(i+2,2,f"{lbl}:",curses.color_pair(C_KEY))
                    win.addstr(i+2,26,val[:bw-28],curses.color_pair(C_DIM))
                except curses.error: pass
            ds_row=len(fields)+3
            try: win.addstr(ds_row,2,"Стратегии (--lua-desync):",curses.color_pair(C_KEY)|curses.A_BOLD)
            except curses.error: pass
            for i,ds in enumerate(profile.get("desync",[])[:4]):
                try: win.addstr(ds_row+1+i,4,f"[{i+1}] {ds[:bw-8]}",curses.color_pair(C_DIM))
                except curses.error: pass
            try: win.addstr(bh-2,2,"e=редактировать поле  d=стратегии  s=сохранить  Esc=отмена",
                            curses.color_pair(C_KEY))
            except curses.error: pass
            win.refresh()
            k=win.getch()
            if k==27: del win; self.scr.touchwin(); self.scr.refresh(); return None
            elif k in (ord('s'),ord('S')): del win; self.scr.touchwin(); self.scr.refresh(); return profile
            elif k in (ord('e'),ord('E')):
                items=[f"{lbl}: {profile.get(key,'')}" for key,lbl in fields]
                del win; self.scr.touchwin(); self.scr.refresh()
                fi=self.menu(items,"Поле",y_off=y+2,x_off=x+2,width=bw-4)
                if fi>=0:
                    key,lbl=fields[fi]
                    val=self.inputbox(lbl,str(profile.get(key,"")),lbl)
                    if val is not None: profile[key]=val
            elif k in (ord('d'),ord('D')):
                del win; self.scr.touchwin(); self.scr.refresh()
                profile["desync"]=self._edit_desync(profile.get("desync",[]))
            try: del win
            except NameError: pass

    def _edit_desync(self, lst: List[str]) -> List[str]:
        lst=list(lst)
        while True:
            items=[f"[{i+1}] {d}" for i,d in enumerate(lst)]
            items+=["  + Добавить","  ✓ Готово"]
            h,w=self.scr.getmaxyx()
            idx=self.menu(items,"lua-desync стратегии",y_off=4,x_off=4,
                          height=min(len(items)+2,h-8),width=min(w-8,72))
            if idx==-1 or idx==len(items)-1: break
            elif idx==len(items)-2:
                v=self.inputbox("Аргумент lua-desync:","fake:blob=fake_default_tls:tcp_md5")
                if v: lst.append(v)
            elif idx<len(lst):
                acts=["Редактировать","Удалить","↑ Вверх","↓ Вниз"]
                act=self.menu(acts,lst[idx][:30],y_off=6,x_off=6)
                if act==0:
                    v=self.inputbox("Аргумент:",lst[idx])
                    if v is not None: lst[idx]=v
                elif act==1:
                    if self.confirm(f"Удалить?\n{lst[idx]}"): lst.pop(idx)
                elif act==2 and idx>0: lst[idx],lst[idx-1]=lst[idx-1],lst[idx]
                elif act==3 and idx<len(lst)-1: lst[idx],lst[idx+1]=lst[idx+1],lst[idx]
        return lst

    # ── Настройки AI провайдера ───────────────────────────────────────────────
    def _setup_ai_provider(self, provider: str):
        """Мастер настройки API ключа для провайдера."""
        info = AI_PROVIDERS[provider]
        cur_key = get_api_key(provider, self.cfg)
        cur_masked = mask_key(cur_key) if cur_key else "(не задан)"
        model = get_model(provider, self.cfg)

        h, w = self.scr.getmaxyx()
        self.msgbox(
            f"Провайдер: {info['name']}\n"
            f"Текущий ключ: {cur_masked}\n"
            f"Модель: {model}\n\n"
            f"Ключ хранится в файле .env (не в коде).\n"
            f"Получить ключ: {info['get_key_url']}",
            f"Настройка {info['name']}"
        )

        key = self.inputbox(
            f"API ключ для {info['name']}:",
            "", f"Введите ключ"
        )
        if key and key.strip():
            key = key.strip()
            # Сохраняем в .env, не в конфиг
            save_api_key_to_env(provider, key)
            save_provider_to_env(provider)
            self.cfg["ai_provider"] = provider
            save_config(self.cfg)
            self.add_log(f"[CFG] Ключ {info['name']} сохранён в .env")

            # Проверяем ключ
            self.scr.clear()
            self.draw_title()
            h2, w2 = self.scr.getmaxyx()
            try:
                self.scr.addstr(h2//2, w2//2-15,
                                "Проверяю ключ…",
                                curses.color_pair(C_AI)|curses.A_BOLD)
            except curses.error: pass
            self.scr.refresh()
            ok, detail = test_api_key(provider, self.cfg)
            if ok:
                self.msgbox(f"✓ {detail}\n\nПровайдер: {info['name']}\nКлюч: {mask_key(key)}", "Успех")
            else:
                self.msgbox(f"✗ Ошибка: {detail}\n\nПроверьте ключ и повторите.", "Ошибка")

    def _select_ai_provider(self):
        """Выбор активного AI провайдера."""
        current = get_active_provider(self.cfg)
        items = []
        for pid, info in AI_PROVIDERS.items():
            key = get_api_key(pid, self.cfg)
            status = f"✓ {mask_key(key)}" if key else "✗ ключ не задан"
            mark = "► " if pid == current else "  "
            items.append(f"{mark}{info['name']}  [{status}]")
        items.append("← Назад")

        h, w = self.scr.getmaxyx()
        idx = self.menu(items, "Выбор AI провайдера",
                        y_off=4, x_off=4,
                        height=min(len(items)+2, h-8),
                        width=min(w-8, 60))
        if idx < 0 or idx == len(items)-1:
            return
        provider = list(AI_PROVIDERS.keys())[idx]
        save_provider_to_env(provider)
        self.cfg["ai_provider"] = provider
        save_config(self.cfg)
        self.add_log(f"[CFG] AI провайдер: {AI_PROVIDERS[provider]['name']}")

    # ── Настройки ─────────────────────────────────────────────────────────────
    def settings_menu(self):
        while True:
            # Zapret настройки
            zap_fields = [
                ("zapret_dir",  "Директория zapret2"),
                ("binary",      "Бинарник nfqws2/winws2"),
                ("lua_lib",     "zapret-lib.lua путь"),
                ("lua_antidpi", "zapret-antidpi.lua путь"),
                ("qnum",        "Номер NFQUEUE"),
            ]
            # Строим список пунктов
            items = [f"{lbl:<28} {str(self.cfg.get(k,''))[:28]}" for k,lbl in zap_fields]

            # AI секция
            provider = get_active_provider(self.cfg)
            pname    = AI_PROVIDERS.get(provider, {}).get("name", provider)
            items.append(f"{'── AI Провайдер':<28} {pname}")

            for pid, info in AI_PROVIDERS.items():
                key = get_api_key(pid, self.cfg)
                val = mask_key(key) if key else "(не задан)"
                items.append(f"  {info['name']:<26} {val}")

            items += ["  Проверить бинарник", "  Проверить безопасность .env", "← Назад"]
            h, w = self.scr.getmaxyx()
            idx = self.menu(items, "Настройки", y_off=2, x_off=2,
                            height=min(len(items)+2, h-4), width=min(w-4, 68))
            total = len(zap_fields) + 1 + len(AI_PROVIDERS)
            if idx == -1 or idx == len(items)-1:
                save_config(self.cfg); break
            elif idx == len(items)-2:
                # Проверка безопасности
                warns = check_env_safety()
                if warns:
                    self.msgbox("\n".join(warns), "Предупреждения безопасности")
                else:
                    self.msgbox("✓ .env файл защищён\n✓ .gitignore настроен", "Безопасность OK")
            elif idx == len(items)-3:
                b = find_binary(self.cfg)
                self.msgbox(f"Бинарник: {b or 'НЕ НАЙДЕН'}", "Проверка")
            elif idx < len(zap_fields):
                k, lbl = zap_fields[idx]
                v = self.inputbox(lbl, str(self.cfg.get(k,"")), lbl)
                if v is not None:
                    self.cfg[k] = v; save_config(self.cfg)
            elif idx == len(zap_fields):
                # Выбор провайдера
                self._select_ai_provider()
            elif idx < total:
                # Настройка конкретного провайдера
                pid = list(AI_PROVIDERS.keys())[idx - len(zap_fields) - 1]
                self._setup_ai_provider(pid)

    # ── Быстрый старт ─────────────────────────────────────────────────────────
    def quick_start(self):
        names=list(STRATEGY_TEMPLATES.keys())
        h,w=self.scr.getmaxyx()
        idx=self.menu(names,"Шаблон стратегии",y_off=3,x_off=3,
                      height=min(len(names)+2,h-6),width=min(w-6,62))
        if idx<0: return
        name=names[idx]; tmpl=STRATEGY_TEMPLATES[name]
        profile=dict(tmpl); profile["name"]=name
        debug=self.confirm(f"Запустить с --debug?\n{tmpl.get('desc','')}","Быстрый старт")
        self.start_zapret(profile,debug=debug)

    def preview_cmd(self):
        all_p=(self.cfg.get("profiles",[]) +
               [{**v,"name":k} for k,v in STRATEGY_TEMPLATES.items()])
        if not all_p: self.msgbox("Нет профилей."); return
        h,w=self.scr.getmaxyx()
        idx=self.menu([p.get("name","?")[:55] for p in all_p],"Предпросмотр команды",
                      y_off=2,x_off=2,height=min(len(all_p)+2,h-4),width=min(w-4,62))
        if idx<0: return
        cmd=build_cmdline(self.cfg,all_p[idx])
        self.msgbox(" ".join(shlex.quote(a) for a in cmd),"Команда запуска")

    def run_blockcheck(self):
        script=os.path.join(self.cfg["zapret_dir"],"blockcheck2.sh")
        if not os.path.isfile(script):
            self.msgbox(f"blockcheck2.sh не найден:\n{script}","Ошибка"); return
        url=self.inputbox("URL для проверки:","https://example.com","blockcheck2")
        if not url: return
        curses.endwin()
        try: subprocess.run(["bash",script,url])
        except Exception: pass
        finally: curses.doupdate(); self.scr.touchwin(); self.scr.refresh()

    # ── Главный экран ─────────────────────────────────────────────────────────
    def draw_main(self):
        h, w = self.scr.getmaxyx()
        pw = min(34, w // 3); ph = h - 3

        # Создаём окна один раз и кешируем
        if not hasattr(self, '_mw') or self._main_size != (h, w):
            self._main_size = (h, w)
            self._mw = curses.newwin(ph, pw, 1, 0)
            self._iw = curses.newwin(ph, w - pw - 1, 1, pw + 1)

        mw = self._mw
        iw = self._iw
        iw_w = w - pw - 1

        # ── Заголовок ────────────────────────────────────────────────────────
        title = " zapret2-tui v2  [AI стратегии] "
        try:
            self.scr.addnstr(0, 0, title.center(w), w - 1,
                             curses.color_pair(C_TITLE) | curses.A_BOLD)
        except curses.error: pass

        # ── Меню ─────────────────────────────────────────────────────────────
        mw.erase()
        mw.bkgd(' ', curses.color_pair(C_MENU))
        self.border_box(mw, "Меню")
        items = [("1","Быстрый старт"), ("2","Мои профили"),
                 ("3","AI подбор стратегии"), ("4","Смешать профили"),
                 ("5","Предпросмотр команды"), ("6","Настройки"),
                 ("7","blockcheck2"),
                 ("8","Хостлисты"),
                 ("9","Мониторинг"),
                 ("W","Watchdog"),
                 ("A","Автозапуск"),
                 ("U","Автообновление"),
                 ("L","Лог"), ("S","Стоп"), ("Q","Выход")]
        for i, (k, lbl) in enumerate(items):
            if i + 2 >= ph - 1: break
            try:
                mw.addstr(i + 2, 2, f" {k} ", curses.color_pair(C_KEY) | curses.A_BOLD)
                mw.addstr(i + 2, 6, lbl[:pw - 8], curses.color_pair(C_MENU))
            except curses.error: pass

        # ── Статус панель ────────────────────────────────────────────────────
        iw.erase()
        iw.bkgd(' ', curses.color_pair(C_MENU))
        self.border_box(iw, "Статус")

        running = self.proc and self.proc.poll() is None
        stxt = "▶ ЗАПУЩЕН" if running else "■ СТОП"
        sa = (curses.color_pair(C_OK) | curses.A_BOLD) if running else curses.color_pair(C_WARN)
        try:
            iw.addstr(2, 3, "Статус: ", curses.color_pair(C_KEY))
            iw.addstr(2, 11, stxt, sa)
            if running:
                iw.addstr(2, 11 + len(stxt) + 1,
                          f"PID={self.proc.pid}"[:iw_w - 16],
                          curses.color_pair(C_DIM))
        except curses.error: pass

        if self.ai_finder and not self._ai_done:
            msg, cur, tot = self.ai_progress
            try:
                iw.addstr(3, 3, "AI: ", curses.color_pair(C_AI) | curses.A_BOLD)
                iw.addstr(3, 7, msg[:iw_w - 9], curses.color_pair(C_AI))
            except curses.error: pass

        b = find_binary(self.cfg)
        provider = get_active_provider(self.cfg)
        pname    = AI_PROVIDERS.get(provider, {}).get("name", provider)
        has_key  = bool(get_api_key(provider, self.cfg))
        wd_on    = self.feat.get("watchdog_enabled", False)
        au_on    = self.feat.get("autoupdate_enabled", False)
        as_on    = self.feat.get("autostart_enabled", False)
        try:
            iw.addstr(5, 3, "Бинарник:  ", curses.color_pair(C_KEY))
            iw.addstr(5, 14, (b or "НЕ НАЙДЕН")[:iw_w - 16],
                      curses.color_pair(C_OK) if b else curses.color_pair(C_WARN))
            iw.addstr(6, 3, "Директория:", curses.color_pair(C_KEY))
            iw.addstr(6, 15, self.cfg["zapret_dir"][:iw_w - 17], curses.color_pair(C_DIM))
            iw.addstr(7, 3, "Профилей:  ", curses.color_pair(C_KEY))
            iw.addstr(7, 14, str(len(self.cfg.get("profiles", []))), curses.color_pair(C_DIM))
            iw.addstr(8, 3, "AI:        ", curses.color_pair(C_KEY))
            ai_s = f"{pname}  {'[ключ OK]' if has_key else '[нет ключа]'}"
            iw.addstr(8, 14, ai_s[:iw_w - 16],
                      curses.color_pair(C_OK) if has_key else curses.color_pair(C_WARN))
            # Статусы фоновых сервисов
            iw.addstr(10, 3, "Watchdog:  ", curses.color_pair(C_KEY))
            iw.addstr(10, 14, "ВКЛ" if wd_on else "выкл",
                      curses.color_pair(C_OK) if wd_on else curses.color_pair(C_DIM))
            iw.addstr(11, 3, "Автозапуск:", curses.color_pair(C_KEY))
            iw.addstr(11, 14, "ВКЛ" if as_on else "выкл",
                      curses.color_pair(C_OK) if as_on else curses.color_pair(C_DIM))
            iw.addstr(12, 3, "Автообновл:", curses.color_pair(C_KEY))
            iw.addstr(12, 14, "ВКЛ" if au_on else "выкл",
                      curses.color_pair(C_OK) if au_on else curses.color_pair(C_DIM))
        except curses.error: pass

        # Лог превью
        try: iw.addstr(14, 3, "Лог:", curses.color_pair(C_KEY))
        except curses.error: pass
        for i, ln in enumerate(self.log_lines[-(ph - 17):]):
            if 15 + i >= ph - 1: break
            if "[AI]" in ln:              a = curses.color_pair(C_AI)
            elif "✓" in ln:              a = curses.color_pair(C_OK)
            elif "✗" in ln or "ОШИБК" in ln.upper(): a = curses.color_pair(C_WARN)
            else:                         a = curses.color_pair(C_DIM)
            try: iw.addstr(15 + i, 3, ln[:iw_w - 5], a)
            except curses.error: pass

        # Статусбар
        self.draw_statusbar()

        # Единый flush — исключает мигание
        mw.noutrefresh()
        iw.noutrefresh()
        curses.doupdate()


    # ══════════════════════════════════════════════════════════════════════════
    #  HOSTLIST EDITOR
    # ══════════════════════════════════════════════════════════════════════════

    def hostlist_editor(self):
        """Полноэкранный редактор хостлистов."""
        while True:
            files = self.hlm.list_files()
            h, w = self.scr.getmaxyx()
            items = []
            for f in files:
                icon = "📋" if f["source"] == "zapret2" else "✏ "
                items.append(f"{icon} {f['name']:<30} {f['count']:>4} доменов  [{f['source']}]")
            items += ["  + Создать новый хостлист",
                      "  📥 Импорт из URL",
                      "  🔍 Мониторинг-лист (домены для дашборда)",
                      "← Назад"]
            idx = self.menu(items, "Редактор хостлистов",
                            y_off=2, x_off=2,
                            height=min(len(items)+2, h-4),
                            width=min(w-4, 72))
            n_files = len(files)
            if idx == -1 or idx == len(items)-1:
                break
            elif idx == n_files:
                self._hl_create_new()
            elif idx == n_files+1:
                self._hl_import_url()
            elif idx == n_files+2:
                self._hl_edit_monitor()
            elif idx < n_files:
                self._hl_open_file(files[idx])

    def _hl_open_file(self, finfo: dict):
        """Открывает файл для редактирования."""
        path    = finfo["path"]
        is_zap  = finfo["source"] == "zapret2"
        while True:
            domains = self.hlm.read_domains(path)
            h, w   = self.scr.getmaxyx()
            title  = f"{finfo['name']} ({len(domains)} доменов)"
            # Строим список доменов
            items = [f"  {d}" for d in domains[:200]]
            if not items:
                items = ["  (файл пуст)"]
            if not is_zap:
                items += ["  + Добавить домен", "  🗑  Очистить всё"]
            items += ["  📊 Использовать в мониторинге", "← Назад"]

            idx = self.menu(items, title,
                            y_off=2, x_off=2,
                            height=min(len(items)+2, h-4),
                            width=min(w-4, 65))
            if idx == -1 or idx == len(items)-1:
                break

            offset = len(domains) if domains else 1  # позиция "+ Добавить"
            if not is_zap and idx == offset:
                # Добавить домен
                d = self.inputbox("Введите домен:", "", "Добавить")
                if d:
                    d = d.strip().lower()
                    self.hlm.add_domain(path, d)
                    self.add_log(f"[HL] Добавлен: {d} → {finfo['name']}")
            elif not is_zap and idx == offset+1:
                # Очистить
                if self.confirm(f"Очистить {finfo['name']}? ({len(domains)} доменов)"):
                    self.hlm.write_domains(path, [])
            elif idx == len(items)-2:
                # Мониторинг
                self._add_to_monitor(domains)
            elif idx < len(domains) and not is_zap:
                # Редактировать/удалить домен
                domain = domains[idx]
                act = self.menu(
                    [f"✏  Редактировать: {domain}",
                     f"🗑  Удалить: {domain}",
                     "← Назад"],
                    "Действие", y_off=5, x_off=5)
                if act == 0:
                    nd = self.inputbox("Домен:", domain)
                    if nd and nd != domain:
                        self.hlm.remove_domain(path, domain)
                        self.hlm.add_domain(path, nd.strip().lower())
                elif act == 1:
                    self.hlm.remove_domain(path, domain)
                    self.add_log(f"[HL] Удалён: {domain}")

    def _hl_create_new(self):
        name = self.inputbox("Имя нового хостлиста (без .txt):", "my-list", "Новый файл")
        if not name:
            return
        domains_raw = self.inputbox("Домены через запятую или пробел:", "", "Домены")
        domains = []
        if domains_raw:
            domains = [d.strip().lower() for d in re.split(r'[,\s]+', domains_raw) if d.strip()]
        path = self.hlm.create_custom(name, domains)
        self.add_log(f"[HL] Создан: {path} ({len(domains)} доменов)")
        self.msgbox(f"Создан файл:\n{path}\n\nДоменов: {len(domains)}", "Готово")

    def _hl_import_url(self):
        url = self.inputbox("URL файла со списком доменов:", "https://", "Импорт из URL")
        if not url or url == "https://":
            return
        name = self.inputbox("Имя файла (без .txt):", "imported", "Имя")
        if not name:
            return
        self.scr.clear(); self.draw_title()
        h, w = self.scr.getmaxyx()
        try:
            self.scr.addstr(h//2, w//2-20,
                            f" Загрузка… {url[:40]} ",
                            curses.color_pair(C_AI)|curses.A_BOLD)
        except curses.error: pass
        self.scr.refresh()
        ok, msg = self.hlm.import_from_url(url, name)
        self.msgbox(msg, "Импорт: " + ("OK" if ok else "Ошибка"))
        if ok:
            self.add_log(f"[HL] Импорт: {msg}")

    def _hl_edit_monitor(self):
        """Редактирует список доменов для мониторинга."""
        path = self.hlm.get_monitor_hostlist()
        self._hl_open_file({
            "name":   "monitor.txt",
            "path":   path,
            "source": "custom",
            "count":  self.hlm._count_lines(path),
        })
        # Перезагружаем домены монитора
        domains = self.hlm.read_domains(path)
        self.monitor.set_domains(domains)
        if domains and not self.monitor._thread:
            self.monitor.start()
        self.feat["monitor_domains"] = domains
        self._save_features(self.feat)

    def _add_to_monitor(self, domains: list):
        """Добавляет список доменов в мониторинг."""
        path = self.hlm.get_monitor_hostlist()
        cur  = self.hlm.read_domains(path)
        added = 0
        for d in domains:
            if d not in cur:
                self.hlm.add_domain(path, d)
                added += 1
        self.monitor.set_domains(self.hlm.read_domains(path))
        if not self.monitor._thread:
            self.monitor.start()
        self.msgbox(f"Добавлено {added} доменов в мониторинг.", "Мониторинг")

    # ══════════════════════════════════════════════════════════════════════════
    #  DASHBOARD — МОНИТОРИНГ ДОСТУПНОСТИ
    # ══════════════════════════════════════════════════════════════════════════

    def show_dashboard(self):
        """Дашборд мониторинга в реальном времени."""
        # Убеждаемся что монитор запущен
        monitor_hl = self.hlm.get_monitor_hostlist()
        domains = self.hlm.read_domains(monitor_hl)
        if not domains:
            choice = self.confirm(
                "Список доменов для мониторинга пуст.\nОткрыть редактор хостлистов?",
                "Нет доменов"
            )
            if choice:
                self._hl_edit_monitor()
            return

        self.monitor.set_domains(domains)
        if not (self.monitor._thread and self.monitor._thread.is_alive()):
            self.monitor.start()

        scroll = 0
        while True:
            self.poll_proc()
            self._draw_dashboard(scroll)
            self.scr.timeout(500)
            k = self.scr.getch()
            if k in (27, ord('q'), ord('Q')):
                break
            elif k == curses.KEY_UP:    scroll = max(0, scroll-1)
            elif k == curses.KEY_DOWN:  scroll += 1
            elif k == curses.KEY_PPAGE: scroll = max(0, scroll-10)
            elif k == curses.KEY_NPAGE: scroll += 10
            elif k == curses.KEY_HOME:  scroll = 0
            elif k in (ord('r'), ord('R')):
                # Принудительная перепроверка всех
                for s in self.monitor.get_statuses():
                    self.monitor.check_now(s.domain)
            elif k in (ord('e'), ord('E')):
                self._hl_edit_monitor()
                domains = self.hlm.read_domains(monitor_hl)
                self.monitor.set_domains(domains)
            elif k in (ord('a'), ord('A')):
                # Добавить домен быстро
                d = self.inputbox("Домен для мониторинга:", "", "Добавить")
                if d:
                    self.hlm.add_domain(monitor_hl, d.strip().lower())
                    self.monitor.set_domains(self.hlm.read_domains(monitor_hl))

    def _draw_dashboard(self, scroll: int = 0):
        """Рисует дашборд мониторинга."""
        self.scr.clear()
        h, w = self.scr.getmaxyx()

        # Заголовок
        title = " 📊 МОНИТОРИНГ ДОСТУПНОСТИ "
        try:
            self.scr.addstr(0, 0,
                            title.center(w),
                            curses.color_pair(C_TITLE)|curses.A_BOLD)
        except curses.error: pass

        statuses = self.monitor.get_statuses()
        total = len(statuses)
        ok_c  = sum(1 for s in statuses if s.ok is True)
        fail_c= sum(1 for s in statuses if s.ok is False)
        unk_c = sum(1 for s in statuses if s.ok is None)

        # Сводка
        try:
            self.scr.addstr(1, 2,
                f" Всего: {total}  ",
                curses.color_pair(C_DIM))
            self.scr.addstr(1, 14,
                f"✓ Доступно: {ok_c}  ",
                curses.color_pair(C_OK)|curses.A_BOLD)
            self.scr.addstr(1, 32,
                f"✗ Недоступно: {fail_c}  ",
                curses.color_pair(C_WARN)|curses.A_BOLD)
            self.scr.addstr(1, 52,
                f"? Проверяется: {unk_c}",
                curses.color_pair(C_DIM))
        except curses.error: pass

        # Заголовок таблицы
        col_w = min(w-2, 78)
        hdr = f" {'ДОМЕН':<28} {'СТАТУС':<12} {'КОД':<8} {'МС':>5}  {'АПТАЙМ':>6}  {'ИСТОРИЯ':<12} {'ПРОВЕРЕН'}"
        try:
            self.scr.addstr(2, 0, hdr[:w-1], curses.color_pair(C_KEY)|curses.A_BOLD)
            self.scr.addstr(3, 0, "─"*min(w-1, col_w), curses.color_pair(C_BORDER))
        except curses.error: pass

        # Строки доменов
        vis_rows = h - 8
        scroll = min(scroll, max(0, total - vis_rows))
        for i in range(vis_rows):
            idx = i + scroll
            if idx >= total:
                break
            s = statuses[idx]
            row = 4 + i

            # Цвет и статус
            if s.ok is True:
                status_str = "● ДОСТУПЕН"
                status_attr = curses.color_pair(C_OK)|curses.A_BOLD
                row_attr   = curses.color_pair(C_OK)
            elif s.ok is False:
                status_str = "✗ БЛОКИРОВАН"
                status_attr = curses.color_pair(C_WARN)|curses.A_BOLD
                row_attr   = curses.color_pair(C_WARN)
            else:
                status_str = "○ проверка…"
                status_attr = curses.color_pair(C_DIM)
                row_attr   = curses.color_pair(C_DIM)

            uptime_str = f"{s.uptime_pct:3d}%" if s.history else "  -  "
            lat_str    = f"{s.latency_ms:4d}" if s.latency_ms else "   -"
            code_str   = s.http_code[:7] if s.http_code else "  -   "
            age_str    = s.age_str

            try:
                # Домен
                self.scr.addstr(row, 1,
                    f" {s.domain:<28}",
                    curses.color_pair(C_DIM))
                # Статус (цветной)
                self.scr.addstr(row, 30,
                    f"{status_str:<12}", status_attr)
                # Код
                self.scr.addstr(row, 43,
                    f"{code_str:<8}", row_attr)
                # Задержка
                self.scr.addstr(row, 51,
                    f"{lat_str:>5}ms", curses.color_pair(C_DIM))
                # Аптайм
                self.scr.addstr(row, 59,
                    f"{uptime_str:>6}", row_attr)
                # История — мини-график с цветами
                self.scr.addstr(row, 67, " ")
                for j, h_ok in enumerate(s.history[-10:]):
                    c = curses.color_pair(C_OK) if h_ok else curses.color_pair(C_WARN)
                    try:
                        self.scr.addstr(row, 68+j, "▓" if h_ok else "░", c)
                    except curses.error: pass
                # Время проверки
                self.scr.addstr(row, 80, f" {age_str}", curses.color_pair(C_DIM))
            except curses.error:
                pass

        # Нижняя панель подсказок
        hint_row = h - 3
        try:
            self.scr.addstr(hint_row, 0, "─"*min(w-1, col_w), curses.color_pair(C_BORDER))
            self.scr.addstr(hint_row+1, 1,
                " R перепроверить  A добавить  E редактировать  ↑↓ прокрутка  Q выход ",
                curses.color_pair(C_KEY))
            # Интервал обновления
            interval = self.feat.get("monitor_interval", 30)
            self.scr.addstr(hint_row+2, 1,
                f" Интервал обновления: {interval}с  |  Мониторинг активен",
                curses.color_pair(C_DIM))
        except curses.error: pass

        self.draw_statusbar()
        self.scr.refresh()

    # ══════════════════════════════════════════════════════════════════════════
    #  WATCHDOG MENU
    # ══════════════════════════════════════════════════════════════════════════

    def watchdog_menu(self):
        while True:
            enabled  = self.feat.get("watchdog_enabled", False)
            interval = self.feat.get("watchdog_interval", 60)
            thresh   = self.feat.get("watchdog_fail_threshold", 3)
            domains  = self.feat.get("watchdog_domains", [])
            wd_run   = self.watchdog._thread and self.watchdog._thread.is_alive()

            status_str = ("▶ АКТИВЕН" if wd_run else "■ ОСТАНОВЛЕН")
            status_col = C_OK if wd_run else C_WARN

            h, w = self.scr.getmaxyx()
            items = [
                f"{'[ВКЛ]' if enabled else '[ВЫКЛ]'}  Watchdog: {status_str}",
                f"   Интервал проверки:   {interval} сек",
                f"   Провалов до смены:   {thresh}",
                f"   Домены для WD:       {len(domains)} ({', '.join(domains[:2])}{'…' if len(domains)>2 else ''})",
                "   Использовать домены из мониторинга",
                "← Назад",
            ]
            idx = self.menu(items, "Watchdog — автопереключение",
                            y_off=3, x_off=3,
                            height=min(len(items)+2, h-6),
                            width=min(w-6, 58))
            if idx in (-1, 5):
                break
            elif idx == 0:
                # Вкл/выкл
                enabled = not enabled
                self.feat["watchdog_enabled"] = enabled
                self._save_features(self.feat)
                if enabled:
                    self.watchdog.start()
                else:
                    self.watchdog.stop()
            elif idx == 1:
                v = self.inputbox("Интервал проверки (секунды):", str(interval))
                if v and v.isdigit():
                    self.feat["watchdog_interval"] = int(v)
                    self._save_features(self.feat)
            elif idx == 2:
                v = self.inputbox("Провалов до переключения:", str(thresh))
                if v and v.isdigit():
                    self.feat["watchdog_fail_threshold"] = int(v)
                    self._save_features(self.feat)
            elif idx == 3:
                raw = self.inputbox("Домены через запятую:", ", ".join(domains))
                if raw is not None:
                    self.feat["watchdog_domains"] = [
                        d.strip() for d in raw.split(",") if d.strip()
                    ]
                    self._save_features(self.feat)
            elif idx == 4:
                # Взять домены из monitor-листа
                monitor_hl = self.hlm.get_monitor_hostlist()
                md = self.hlm.read_domains(monitor_hl)
                if md:
                    self.feat["watchdog_domains"] = md[:10]
                    self._save_features(self.feat)
                    self.msgbox(f"Загружено {min(len(md),10)} доменов из monitor.txt", "OK")
                else:
                    self.msgbox("monitor.txt пуст. Добавьте домены в Редактор хостлистов.", "Пусто")

    # ══════════════════════════════════════════════════════════════════════════
    #  AUTOSTART MENU
    # ══════════════════════════════════════════════════════════════════════════

    def autostart_menu(self):
        while True:
            is_avail = self.autostart.is_systemd_available()
            status   = self.autostart.get_status() if is_avail else "н/д"
            enabled  = self.feat.get("autostart_enabled", False)
            profile  = self.feat.get("autostart_profile", "(не задан)")
            h, w     = self.scr.getmaxyx()

            items = [
                f"Systemd: {'доступен' if is_avail else 'НЕ ДОСТУПЕН'}   Статус: {status}",
                f"{'[ВКЛ]' if enabled else '[ВЫКЛ]'}  Автозапуск при старте системы",
                f"   Профиль: {profile}",
                "   Установить/обновить юнит",
                "   Показать unit файл",
                "   Удалить автозапуск",
                "← Назад",
            ]
            idx = self.menu(items, "Автозапуск (systemd)",
                            y_off=3, x_off=3,
                            height=min(len(items)+2, h-6),
                            width=min(w-6, 62))
            if idx in (-1, 6):
                break
            elif idx == 1:
                if not is_avail:
                    self.msgbox("systemd недоступен на этой системе.", "Ошибка"); continue
                ok, msg = self.autostart.toggle()
                self.msgbox(msg, "OK" if ok else "Ошибка")
            elif idx == 2:
                # Выбрать профиль
                profiles = self.cfg.get("profiles", [])
                if not profiles:
                    self.msgbox("Нет сохранённых профилей."); continue
                names = [p.get("name","?") for p in profiles]
                pi = self.menu(names, "Профиль для автозапуска",
                               y_off=5, x_off=5,
                               height=min(len(names)+2, h-8),
                               width=min(w-8, 60))
                if pi >= 0:
                    self.feat["autostart_profile"] = profiles[pi].get("name","")
                    self._save_features(self.feat)
            elif idx == 3:
                # Установить юнит
                pname = self.feat.get("autostart_profile","")
                if not pname:
                    self.msgbox("Сначала выберите профиль (пункт 3)."); continue
                profiles = self.cfg.get("profiles", [])
                profile_obj = next((p for p in profiles if p.get("name")==pname), None)
                if not profile_obj:
                    self.msgbox(f"Профиль '{pname}' не найден."); continue
                cmd = build_cmdline(self.cfg, profile_obj)
                ok, msg = self.autostart.install(pname, cmd)
                self.msgbox(msg, "Установка: " + ("OK" if ok else "Ошибка"))
                if ok: self.add_log(f"[AS] {msg}")
            elif idx == 4:
                self.msgbox(self.autostart.show_unit(), "Unit файл")
            elif idx == 5:
                if self.confirm("Удалить автозапуск zapret2?"):
                    ok, msg = self.autostart.remove()
                    self.msgbox(msg, "OK" if ok else "Ошибка")

    # ══════════════════════════════════════════════════════════════════════════
    #  AUTO-UPDATE MENU
    # ══════════════════════════════════════════════════════════════════════════

    def autoupdate_menu(self):
        while True:
            enabled  = self.feat.get("autoupdate_enabled", False)
            interval = self.feat.get("autoupdate_interval", 604800) // 86400  # в днях
            next_run = self.updater.next_run_str
            h, w     = self.scr.getmaxyx()

            items = [
                f"{'[ВКЛ]' if enabled else '[ВЫКЛ]'}  Автообновление стратегий",
                f"   Интервал:     каждые {interval} дн.",
                f"   Следующий:    {next_run}",
                "   Запустить обновление сейчас",
                "← Назад",
            ]
            idx = self.menu(items, "Автообновление стратегий",
                            y_off=3, x_off=3,
                            height=min(len(items)+2, h-6),
                            width=min(w-6, 55))
            if idx in (-1, 4):
                break
            elif idx == 0:
                enabled = not enabled
                self.feat["autoupdate_enabled"] = enabled
                self._save_features(self.feat)
                if enabled:
                    self.updater.start()
                else:
                    self.updater.stop()
            elif idx == 1:
                v = self.inputbox("Интервал обновления (дней):", str(interval))
                if v and v.isdigit():
                    self.feat["autoupdate_interval"] = int(v) * 86400
                    self._save_features(self.feat)
            elif idx == 3:
                if self.confirm("Запустить проверку новых стратегий через AI?"):
                    self.updater.run_now()
                    self.msgbox("Обновление запущено в фоне.\nРезультаты появятся в Профилях и Логе.", "Запущено")


    # ── Главный цикл ─────────────────────────────────────────────────────────
    def main_loop(self):
        while True:
            self.poll_proc()
            # Проверяем новые AI результаты и сохраняем
            with self._ai_lock:
                if self.ai_new_results:
                    for p in self.ai_new_results:
                        if p not in self.cfg.get("profiles",[]):
                            self.cfg.setdefault("profiles",[]).append(p)
                    save_config(self.cfg)

            self.draw_main()
            self.scr.timeout(300)
            k=self.scr.getch()

            if k in (ord('q'),ord('Q')):
                if self.proc and self.proc.poll() is None:
                    if self.confirm("zapret2 запущен. Остановить перед выходом?"):
                        self.stop_zapret()
                if self.ai_finder and not self._ai_done:
                    if self.confirm("AI подбор идёт. Остановить?"):
                        self.ai_finder.stop()
                break
            elif k==ord('1'): self.quick_start()
            elif k==ord('2'): self.profiles_menu()
            elif k==ord('3'): self.ai_strategy_menu()
            elif k==ord('4'): self._mix_profiles_menu()
            elif k==ord('5'): self.preview_cmd()
            elif k==ord('6'): self.settings_menu()
            elif k==ord('7'): self.run_blockcheck()
            elif k==ord('8'): self.hostlist_editor()
            elif k==ord('9'): self.show_dashboard()
            elif k in (ord('w'),ord('W')): self.watchdog_menu()
            elif k in (ord('a'),ord('A')): self.autostart_menu()
            elif k in (ord('u'),ord('U')): self.autoupdate_menu()
            elif k in (ord('l'),ord('L')): self.show_log()
            elif k in (ord('s'),ord('S')):
                if self.proc and self.proc.poll() is None:
                    if self.confirm("Остановить zapret2?"): self.stop_zapret()
                else: self.status_msg="Процесс не запущен"

        self.stop_zapret()
        self.monitor.stop()
        self.watchdog.stop()
        self.updater.stop()
        if self.ai_finder and not self._ai_done:
            self.ai_finder.stop()

# ──────────────────────────────────────────────────────────────────────────────

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zapret2-tui.log")

def _write_crash_log(exc: Exception):
    import traceback
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            import datetime
            f.write(f"\n{'='*60}\n")
            f.write(f"CRASH {datetime.datetime.now()}\n")
            f.write(traceback.format_exc())
            f.write(f"{'='*60}\n")
    except Exception:
        pass

def main():
    # Предварительная проверка импортов ДО запуска curses
    # чтобы ошибка импорта выводилась нормально в терминал
    missing = []
    for mod in ("zapret2_config", "zapret2_ai", "zapret2_tui_helpers", "zapret2_features"):
        try:
            __import__(mod)
        except ImportError as e:
            missing.append(f"  {mod}: {e}")
        except Exception as e:
            missing.append(f"  {mod}: {e}")

    if missing:
        print("ОШИБКА: не удалось загрузить модули:")
        for m in missing:
            print(m)
        print(f"\nУбедитесь что все файлы лежат в одной папке:")
        print("  zapret2-tui-v2.py")
        print("  zapret2_config.py")
        print("  zapret2_ai.py")
        print("  zapret2_tui_helpers.py")
        print("  zapret2_features.py")
        sys.exit(1)

    def run(scr):
        try:
            ZapretTUI(scr)
        except Exception as e:
            # Восстанавливаем терминал перед выводом ошибки
            try:
                curses.nocbreak()
                scr.keypad(False)
                curses.echo()
                curses.endwin()
            except Exception:
                pass
            _write_crash_log(e)
            import traceback
            print("\n" + "="*60)
            print("ОШИБКА запret2-tui:")
            print("="*60)
            traceback.print_exc()
            print("="*60)
            print(f"\nПолный лог сохранён в: {LOG_FILE}")
            print("Нажмите Enter для выхода...")
            try:
                input()
            except Exception:
                pass
            raise  # пробрасываем чтобы curses.wrapper сам восстановил терминал

    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        pass
    except Exception:
        pass  # уже обработано внутри run()

    print("\nzapret2-tui завершён.")

if __name__ == "__main__":
    main()

