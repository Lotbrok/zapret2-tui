"""
zapret2_features.py — дополнительные модули для zapret2-tui v3

Содержит:
  - HostlistManager  — редактор хостлистов (используется везде)
  - DomainMonitor    — мониторинг доступности доменов в реальном времени
  - Watchdog         — фоновый наблюдатель, автопереключение стратегий
  - AutostartManager — управление systemd unit файлом
  - StrategyUpdater  — автообновление стратегий через AI
"""

import os, json, re, time, threading, subprocess, datetime, socket
import urllib.request, urllib.error
from typing import List, Dict, Optional, Callable, Tuple

# ─── Пути ────────────────────────────────────────────────────────────────────

HERE          = os.path.dirname(os.path.abspath(__file__))
HOSTLISTS_DIR = os.path.join(HERE, "hostlists")
FEATURES_CFG  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zapret2-features.json")
SYSTEMD_UNIT  = "/etc/systemd/system/zapret2.service"

DEFAULT_FEATURES = {
    "watchdog_enabled":        False,
    "watchdog_interval":       60,      # секунд между проверками
    "watchdog_fail_threshold": 3,       # сколько провалов до переключения
    "watchdog_domains":        [],      # домены для watchdog (берём из hostlist monitor)
    "autostart_enabled":       False,
    "autostart_profile":       "",      # имя профиля для автозапуска
    "autoupdate_enabled":      False,
    "autoupdate_interval":     604800,  # 7 дней в секундах
    "autoupdate_last_run":     0,
    "monitor_domains":         [],      # домены для дашборда
    "monitor_interval":        30,      # секунд между проверками дашборда
}


def load_features() -> dict:
    if os.path.isfile(FEATURES_CFG):
        try:
            cfg = json.load(open(FEATURES_CFG, encoding="utf-8"))
            for k, v in DEFAULT_FEATURES.items():
                cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return dict(DEFAULT_FEATURES)


def save_features(cfg: dict):
    json.dump(cfg, open(FEATURES_CFG, "w", encoding="utf-8"), indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════════════
#  HOSTLIST MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class HostlistManager:
    """Управление файлами хостлистов."""

    BUNDLED = {
        "youtube":   "list-youtube.txt",
        "discord":   "list-discord.txt",
        "torrents":  "list-torrents.txt",
    }

    def __init__(self, zapret_dir: str):
        self.zapret_dir = zapret_dir
        self.custom_dir = HOSTLISTS_DIR
        os.makedirs(self.custom_dir, exist_ok=True)

    # ── Список всех хостлистов ────────────────────────────────────────────────

    def list_files(self) -> List[Dict]:
        """Возвращает все доступные хостлист файлы."""
        result = []
        # Встроенные zapret2
        files_dir = os.path.join(self.zapret_dir, "files")
        if os.path.isdir(files_dir):
            for fname in sorted(os.listdir(files_dir)):
                if fname.endswith(".txt"):
                    path = os.path.join(files_dir, fname)
                    result.append({
                        "name":   fname,
                        "path":   path,
                        "source": "zapret2",
                        "count":  self._count_lines(path),
                    })
        # Пользовательские
        for fname in sorted(os.listdir(self.custom_dir)):
            if fname.endswith(".txt"):
                path = os.path.join(self.custom_dir, fname)
                result.append({
                    "name":   fname,
                    "path":   path,
                    "source": "custom",
                    "count":  self._count_lines(path),
                })
        return result

    def _count_lines(self, path: str) -> int:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                return sum(1 for ln in f if ln.strip() and not ln.startswith("#"))
        except Exception:
            return 0

    # ── Чтение / запись ───────────────────────────────────────────────────────

    def read_domains(self, path: str) -> List[str]:
        """Читает список доменов из файла."""
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                return [ln.strip() for ln in f
                        if ln.strip() and not ln.startswith("#")]
        except Exception:
            return []

    def write_domains(self, path: str, domains: List[str]):
        """Записывает список доменов в файл."""
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# zapret2-tui hostlist\n")
            f.write(f"# Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            for d in sorted(set(domains)):
                f.write(d + "\n")

    def create_custom(self, name: str, domains: List[str]) -> str:
        """Создаёт новый пользовательский хостлист."""
        if not name.endswith(".txt"):
            name += ".txt"
        path = os.path.join(self.custom_dir, name)
        self.write_domains(path, domains)
        return path

    def add_domain(self, path: str, domain: str):
        domains = self.read_domains(path)
        domain = domain.strip().lower()
        if domain and domain not in domains:
            domains.append(domain)
            self.write_domains(path, domains)

    def remove_domain(self, path: str, domain: str):
        domains = self.read_domains(path)
        domains = [d for d in domains if d != domain]
        self.write_domains(path, domains)

    def get_monitor_hostlist(self) -> str:
        """Возвращает путь к файлу мониторинга (создаёт если нет)."""
        path = os.path.join(self.custom_dir, "monitor.txt")
        if not os.path.isfile(path):
            self.write_domains(path, [])
        return path

    # ── Импорт из URL ─────────────────────────────────────────────────────────

    def import_from_url(self, url: str, name: str,
                        progress_cb: Callable[[str], None] = None) -> Tuple[bool, str]:
        try:
            if progress_cb:
                progress_cb(f"Загрузка {url}…")
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                content = r.read().decode("utf-8", errors="ignore")
            domains = [ln.strip() for ln in content.splitlines()
                       if ln.strip() and not ln.startswith("#")]
            path = self.create_custom(name, domains)
            return True, f"Импортировано {len(domains)} доменов → {path}"
        except Exception as e:
            return False, str(e)


# ═══════════════════════════════════════════════════════════════════════════════
#  DOMAIN MONITOR
# ═══════════════════════════════════════════════════════════════════════════════

class DomainStatus:
    """Статус одного домена."""
    __slots__ = ["domain", "ok", "latency_ms", "http_code", "last_check", "history", "error"]

    def __init__(self, domain: str):
        self.domain     = domain
        self.ok         = None          # True/False/None (не проверялся)
        self.latency_ms = 0
        self.http_code  = ""
        self.last_check = 0.0
        self.history: List[bool] = []   # последние 10 результатов
        self.error      = ""

    @property
    def uptime_pct(self) -> int:
        if not self.history:
            return 0
        return int(sum(self.history) / len(self.history) * 100)

    @property
    def bar(self) -> str:
        """ASCII мини-график истории (10 символов)."""
        if not self.history:
            return "──────────"
        return "".join("▓" if h else "░" for h in self.history[-10:])

    @property
    def age_str(self) -> str:
        if not self.last_check:
            return "никогда"
        age = time.time() - self.last_check
        if age < 60:   return f"{int(age)}с"
        if age < 3600: return f"{int(age/60)}м"
        return f"{int(age/3600)}ч"


def check_domain(domain: str, timeout: int = 6) -> Tuple[bool, int, str, str]:
    """
    Проверяет доступность домена.
    Возвращает (ok, latency_ms, http_code, error).
    """
    url = f"https://{domain}" if not domain.startswith("http") else domain
    t0 = time.time()
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", str(timeout), "--connect-timeout", "4",
             "-L", "--insecure", url],
            capture_output=True, text=True, timeout=timeout + 2)
        latency = int((time.time() - t0) * 1000)
        code = result.stdout.strip()
        ok = code.isdigit() and 200 <= int(code) < 400
        return ok, latency, code, ""
    except FileNotFoundError:
        # fallback: TCP connect
        t0 = time.time()
        try:
            sock = socket.create_connection((domain, 443), timeout=timeout)
            sock.close()
            latency = int((time.time() - t0) * 1000)
            return True, latency, "TCP OK", ""
        except Exception as e:
            return False, 0, "", str(e)
    except subprocess.TimeoutExpired:
        return False, timeout * 1000, "", "timeout"
    except Exception as e:
        return False, 0, "", str(e)


class DomainMonitor:
    """
    Фоновый монитор доступности доменов.
    Обновляет статусы в отдельном потоке.
    """

    def __init__(self, interval: int = 30):
        self.interval  = interval
        self.statuses: Dict[str, DomainStatus] = {}
        self._lock     = threading.Lock()
        self._stop     = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.on_update: Optional[Callable] = None   # callback при обновлении

    def set_domains(self, domains: List[str]):
        with self._lock:
            # Добавляем новые
            for d in domains:
                if d not in self.statuses:
                    self.statuses[d] = DomainStatus(d)
            # Удаляем ушедшие
            for d in list(self.statuses.keys()):
                if d not in domains:
                    del self.statuses[d]

    def get_statuses(self) -> List[DomainStatus]:
        with self._lock:
            return list(self.statuses.values())

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def check_now(self, domain: str):
        """Немедленная проверка одного домена."""
        threading.Thread(target=self._check_one, args=(domain,), daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            with self._lock:
                domains = list(self.statuses.keys())
            for domain in domains:
                if self._stop.is_set():
                    break
                self._check_one(domain)
                # Небольшая пауза между проверками чтобы не флудить
                self._stop.wait(0.5)
            # Ждём до следующего цикла
            self._stop.wait(self.interval)

    def _check_one(self, domain: str):
        ok, lat, code, err = check_domain(domain)
        with self._lock:
            if domain not in self.statuses:
                return
            s = self.statuses[domain]
            s.ok         = ok
            s.latency_ms = lat
            s.http_code  = code
            s.last_check = time.time()
            s.error      = err
            s.history.append(ok)
            if len(s.history) > 20:
                s.history = s.history[-20:]
        if self.on_update:
            try:
                self.on_update()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
#  WATCHDOG
# ═══════════════════════════════════════════════════════════════════════════════

class Watchdog:
    """
    Следит за доступностью доменов.
    Если N проверок подряд проваливаются — вызывает callback переключения.
    """

    def __init__(self, cfg: dict, features: dict,
                 log_cb: Callable[[str], None],
                 switch_cb: Callable[[], None],   # вызывается когда надо переключить стратегию
                 get_proc_cb: Callable):           # возвращает текущий subprocess.Popen или None
        self.cfg       = cfg
        self.feat      = features
        self.log       = log_cb
        self.switch_cb = switch_cb
        self.get_proc  = get_proc_cb
        self._stop     = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._fail_counts: Dict[str, int] = {}

    @property
    def enabled(self) -> bool:
        return self.feat.get("watchdog_enabled", False)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log("[WD] Watchdog запущен")

    def stop(self):
        self._stop.set()
        self.log("[WD] Watchdog остановлен")

    def _loop(self):
        while not self._stop.is_set():
            interval = self.feat.get("watchdog_interval", 60)
            self._stop.wait(interval)
            if self._stop.is_set():
                break
            if not self.enabled:
                continue
            # Проверяем только если zapret запущен
            proc = self.get_proc()
            if not proc or proc.poll() is not None:
                continue
            self._check_all()

    def _check_all(self):
        domains = self.feat.get("watchdog_domains", [])
        if not domains:
            return
        threshold = self.feat.get("watchdog_fail_threshold", 3)
        all_fail = True

        for domain in domains[:5]:  # проверяем максимум 5 доменов
            ok, lat, code, err = check_domain(domain, timeout=8)
            if ok:
                self._fail_counts[domain] = 0
                all_fail = False
                self.log(f"[WD] ✓ {domain} ({lat}ms)")
            else:
                cnt = self._fail_counts.get(domain, 0) + 1
                self._fail_counts[domain] = cnt
                self.log(f"[WD] ✗ {domain} (провал #{cnt})")

        # Если ВСЕ домены падают N раз подряд — переключаем стратегию
        if all_fail:
            consecutive = min(self._fail_counts.get(d, 0) for d in domains[:5])
            if consecutive >= threshold:
                self.log(f"[WD] ⚠ Все домены недоступны {consecutive} раз подряд — переключаю стратегию!")
                self._fail_counts = {}
                try:
                    self.switch_cb()
                except Exception as e:
                    self.log(f"[WD] Ошибка переключения: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTOSTART MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class AutostartManager:
    """Управление автозапуском через systemd."""

    def __init__(self, cfg: dict, features: dict, log_cb: Callable[[str], None]):
        self.cfg  = cfg
        self.feat = features
        self.log  = log_cb

    def is_systemd_available(self) -> bool:
        return (os.path.isdir("/etc/systemd/system") and
                subprocess.run(["which", "systemctl"],
                               capture_output=True).returncode == 0)

    def get_status(self) -> str:
        """Возвращает статус systemd юнита."""
        if not self.is_systemd_available():
            return "systemd недоступен"
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "zapret2"],
                capture_output=True, text=True)
            status = r.stdout.strip()
            r2 = subprocess.run(
                ["systemctl", "is-enabled", "zapret2"],
                capture_output=True, text=True)
            enabled = r2.stdout.strip()
            return f"{status} / {enabled}"
        except Exception as e:
            return str(e)

    def generate_unit(self, profile_name: str, cmd: List[str]) -> str:
        """Генерирует содержимое systemd unit файла."""
        exec_cmd = " ".join(cmd)
        return f"""[Unit]
Description=zapret2 DPI bypass (profile: {profile_name})
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_cmd}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zapret2

[Install]
WantedBy=multi-user.target
"""

    def install(self, profile_name: str, cmd: List[str]) -> Tuple[bool, str]:
        """Устанавливает systemd юнит."""
        if not self.is_systemd_available():
            return False, "systemd недоступен на этой системе"
        unit_content = self.generate_unit(profile_name, cmd)
        try:
            # Пишем через sudo tee
            proc = subprocess.run(
                ["sudo", "tee", SYSTEMD_UNIT],
                input=unit_content, text=True,
                capture_output=True)
            if proc.returncode != 0:
                return False, f"Ошибка записи: {proc.stderr}"
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
            subprocess.run(["sudo", "systemctl", "enable",  "zapret2"], check=True)
            subprocess.run(["sudo", "systemctl", "restart", "zapret2"], check=True)
            self.feat["autostart_enabled"] = True
            self.feat["autostart_profile"] = profile_name
            save_features(self.feat)
            self.log(f"[AS] Автозапуск установлен для профиля: {profile_name}")
            return True, f"Установлен и запущен: {SYSTEMD_UNIT}"
        except subprocess.CalledProcessError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

    def remove(self) -> Tuple[bool, str]:
        """Удаляет systemd юнит."""
        try:
            subprocess.run(["sudo", "systemctl", "stop",    "zapret2"], capture_output=True)
            subprocess.run(["sudo", "systemctl", "disable", "zapret2"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", SYSTEMD_UNIT],          capture_output=True)
            subprocess.run(["sudo", "systemctl", "daemon-reload"],       capture_output=True)
            self.feat["autostart_enabled"] = False
            save_features(self.feat)
            self.log("[AS] Автозапуск удалён")
            return True, "Автозапуск отключён"
        except Exception as e:
            return False, str(e)

    def toggle(self) -> Tuple[bool, str]:
        """Включить/выключить без удаления юнита."""
        try:
            status = self.get_status()
            if "enabled" in status:
                subprocess.run(["sudo", "systemctl", "disable", "zapret2"], check=True)
                subprocess.run(["sudo", "systemctl", "stop",    "zapret2"], capture_output=True)
                self.feat["autostart_enabled"] = False
                save_features(self.feat)
                return True, "Автозапуск выключен"
            else:
                subprocess.run(["sudo", "systemctl", "enable",  "zapret2"], check=True)
                subprocess.run(["sudo", "systemctl", "restart", "zapret2"], check=True)
                self.feat["autostart_enabled"] = True
                save_features(self.feat)
                return True, "Автозапуск включён"
        except Exception as e:
            return False, str(e)

    def show_unit(self) -> str:
        """Показывает содержимое установленного юнита."""
        if os.path.isfile(SYSTEMD_UNIT):
            try:
                return open(SYSTEMD_UNIT).read()
            except Exception:
                pass
        return "Файл юнита не найден"


# ═══════════════════════════════════════════════════════════════════════════════
#  STRATEGY AUTO-UPDATER
# ═══════════════════════════════════════════════════════════════════════════════

class StrategyUpdater:
    """
    Автоматическое обновление стратегий через AI.
    Раз в N дней проверяет форумы и обновляет профили.
    """

    def __init__(self, cfg: dict, features: dict,
                 log_cb: Callable[[str], None],
                 new_profile_cb: Callable[[dict], None]):
        self.cfg          = cfg
        self.feat         = features
        self.log          = log_cb
        self.new_profile  = new_profile_cb
        self._stop        = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def enabled(self) -> bool:
        return self.feat.get("autoupdate_enabled", False)

    @property
    def next_run_str(self) -> str:
        last = self.feat.get("autoupdate_last_run", 0)
        interval = self.feat.get("autoupdate_interval", 604800)
        if not last:
            return "при первом запуске"
        nxt = last + interval
        delta = nxt - time.time()
        if delta <= 0:
            return "сейчас"
        d = int(delta // 86400)
        h = int((delta % 86400) // 3600)
        return f"через {d}д {h}ч"

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.log("[UPD] Автообновление стратегий запущено")

    def stop(self):
        self._stop.set()

    def run_now(self):
        """Запустить обновление немедленно."""
        threading.Thread(target=self._update, daemon=True).start()

    def _loop(self):
        while not self._stop.is_set():
            if not self.enabled:
                self._stop.wait(60)
                continue
            last     = self.feat.get("autoupdate_last_run", 0)
            interval = self.feat.get("autoupdate_interval", 604800)
            if time.time() - last >= interval:
                self._update()
            self._stop.wait(3600)  # проверяем каждый час нужно ли обновлять

    def _update(self):
        self.log("[UPD] Запуск автообновления стратегий…")
        try:
            from zapret2_ai import call_ai, parse_json_candidates, SYSTEM_EXPERT
            from zapret2_config import get_active_provider, get_api_key
        except ImportError as e:
            self.log(f"[UPD] Ошибка импорта: {e}")
            return

        provider = get_active_provider(self.cfg)
        if not get_api_key(provider, self.cfg):
            self.log("[UPD] Нет API ключа — пропускаю автообновление")
            return

        prompt = """Search for the latest zapret2 / nfqws bypass strategies that work in 2025.
Look for recent discussions on ntc.party, habr.com, GitHub issues about zapret2.
Focus on strategies for: YouTube, Instagram, TikTok, Discord, Telegram.

Return ONLY a JSON array of up to 8 strategies (no text, no markdown):
[{"name":"..","source":"URL","filter_tcp":"443","filter_udp":"","filter_l7":"tls",
"out_range":"-d10","desync":["arg1","arg2"],"multiprofile":false,"profiles":[]}]"""

        from zapret2_config import AI_PROVIDERS
        provider_id = get_active_provider(self.cfg)
        use_search  = (provider_id == "claude")

        text = call_ai(self.cfg,
                       [{"role":"user","content":prompt}],
                       SYSTEM_EXPERT,
                       use_web_search=use_search)
        if not text:
            self.log("[UPD] Нет ответа от AI")
            return

        candidates = parse_json_candidates(text)
        if not candidates:
            self.log("[UPD] Не удалось разобрать ответ AI")
            return

        count = 0
        for c in candidates:
            c["name"]   = f"[Авто {datetime.date.today()}] {c.get('name','?')}"
            c["source"] = c.get("source","autoupdate")
            self.new_profile(c)
            count += 1

        self.feat["autoupdate_last_run"] = time.time()
        save_features(self.feat)
        self.log(f"[UPD] Автообновление завершено: +{count} стратегий")
