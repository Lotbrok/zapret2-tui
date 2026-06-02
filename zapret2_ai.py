"""
zapret2_ai.py — AI-модуль подбора стратегий обхода для zapret2-tui

Алгоритм работы:
1. Поиск в интернете готовых решений для конкретного домена/сервиса
2. Генерация кандидатов стратегий через Claude API (осведомлён о zapret2)
3. Тестирование каждой стратегии через curl (HTTP/HTTPS доступность)
4. Сохранение успешной стратегии как именованного профиля
5. Миксование нескольких стратегий в мульти-профиль
"""

import json
import os
import re
import subprocess
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import List, Dict, Optional, Callable, Tuple

# ─── Константы ────────────────────────────────────────────────────────────────

CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL   = "claude-sonnet-4-20250514"

# Все известные --lua-desync функции из zapret-antidpi.lua
DESYNC_FUNCTIONS = [
    "fake", "fakedsplit", "multisplit", "multidisorder",
    "syndata", "wssize", "oob", "pktmod", "tcpseg",
    "send", "drop", "luaexec",
]

# Всевозможные "fooling" параметры
FOOLING_PARAMS = [
    "tcp_md5", "tcp_ts_up", "ip_ttl", "ip_autottl",
    "ip6_ttl", "ip6_autottl", "tcp_seq", "tcp_ack",
    "datanoack", "badseq",
]

# Матрица кандидатов — стратегии от простых к сложным
CANDIDATE_MATRIX = [
    # (tcp_ports, filter_l7, out_range, desync_list)
    ("443", "tls", "-d10", [
        "fake:blob=fake_default_tls:tcp_md5:repeats=6",
        "multidisorder:pos=midsld",
    ]),
    ("443", "tls", "-d10", [
        "fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6",
        "multidisorder:pos=midsld",
    ]),
    ("443", "tls", "-d10", [
        "fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com",
        "multidisorder:pos=1,midsld",
    ]),
    ("443", "tls", "-d10", [
        "fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5",
        "fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5",
    ]),
    ("443", "tls", "-d10", [
        "fake:blob=fake_default_tls:tcp_md5:repeats=6:tls_mod=rnd,rndsni,dupsid",
        "multisplit:pos=1:seqovl=5",
    ]),
    ("443", "tls", "-d10", [
        "wssize:wsize=1:scale=6",
        "syndata",
        "multisplit:pos=midsld",
    ]),
    ("80,443", "tls,http", "-d10", [
        "fake:blob=fake_default_tls:tcp_md5",
        "multidisorder:pos=midsld",
    ]),
    ("443", "tls", "-d10", [
        "fake:blob=fake_default_tls:tcp_flags_unset=ack:tls_mod=rnd,rndsni,dupsid",
    ]),
    ("443", "tls", "-d10", [
        "fakedsplit:ip_autottl=-1,3-20:tcp_md5",
    ]),
    ("443", "tls", "-d10", [
        "multisplit:pos=1,midsld",
    ]),
]

# Multiport кандидаты (HTTP+HTTPS+QUIC)
MULTIPORT_CANDIDATE = {
    "multiprofile": True,
    "profiles": [
        {"filter_tcp": "80", "filter_l7": "http", "out_range": "-d10",
         "desync": ["fake:blob=fake_default_http:ip_autottl=-2,3-20:tcp_md5",
                    "fakedsplit:ip_autottl=-2,3-20:tcp_md5"]},
        {"filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
         "desync": ["fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6",
                    "multidisorder:pos=midsld"]},
        {"filter_udp": "443", "filter_l7": "quic",
         "desync": ["fake:blob=fake_default_quic:repeats=11"]},
    ]
}

# ─── Проверка доступности ─────────────────────────────────────────────────────

def check_connectivity(domain: str, timeout: int = 8) -> Tuple[bool, str]:
    """Проверяет доступность домена через curl. Возвращает (ok, detail)."""
    url = f"https://{domain}" if not domain.startswith("http") else domain
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", str(timeout),
             "--connect-timeout", "5",
             "-L", "--insecure", url],
            capture_output=True, text=True, timeout=timeout + 3
        )
        code = result.stdout.strip()
        ok = code.isdigit() and 200 <= int(code) < 400
        return ok, f"HTTP {code}"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except FileNotFoundError:
        # curl не установлен — fallback на urllib
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return True, f"HTTP {resp.status}"
        except Exception as e:
            return False, str(e)
    except Exception as e:
        return False, str(e)

def wait_for_connectivity(domain: str, retries: int = 3,
                          delay: float = 2.0) -> Tuple[bool, str]:
    """Несколько попыток проверки доступности."""
    for i in range(retries):
        if i > 0:
            time.sleep(delay)
        ok, detail = check_connectivity(domain)
        if ok:
            return True, detail
    return False, "недоступен после нескольких попыток"

# ─── Веб-поиск готовых решений ────────────────────────────────────────────────

def search_solutions_via_api(domain: str, log_cb: Callable[[str], None]) -> List[Dict]:
    """
    Запрашивает Claude с web_search — ищет в интернете готовые zapret/nfqws
    конфиги для данного домена, возвращает список профилей.
    """
    log_cb(f"[AI] Поиск готовых решений для {domain} в интернете…")

    service_name = _guess_service_name(domain)

    prompt = f"""You are an expert on zapret2 anti-DPI software (https://github.com/bol-van/zapret2).

Search the web for existing working zapret / nfqws / zapret2 bypass configurations for: **{domain}** ({service_name}).

Look for:
- GitHub issues, discussions, gists mentioning nfqws or zapret configs for {service_name}
- Russian forums (habr, 4pda, ntc.party) with working bypass strategies
- Any --lua-desync or --dpi-desync parameters that reportedly work for {service_name} in Russia or similar DPI environments

After searching, return a JSON array (and NOTHING else, no markdown, no preamble) with up to 5 candidate strategy profiles.
Each profile object must have these fields:
{{
  "name": "short descriptive name",
  "source": "where you found it (URL or 'generated')",
  "filter_tcp": "443",
  "filter_udp": "",
  "filter_l7": "tls",
  "out_range": "-d10",
  "desync": ["lua-desync-arg1", "lua-desync-arg2"],
  "multiprofile": false,
  "profiles": []
}}

If multiprofile is true, fill "profiles" array with sub-profiles (each with filter_tcp/udp/l7/out_range/desync).
Use only valid zapret2 --lua-desync arguments like: fake:blob=fake_default_tls:tcp_md5:repeats=6, multidisorder:pos=midsld, fakedsplit:ip_autottl=-2,3-20:tcp_md5, etc.
Return ONLY the JSON array. No explanation."""

    try:
        payload = {
            "model": CLAUDE_MODEL,
            "max_tokens": 2000,
            "tools": [{"type": "web_search_20250305", "name": "web_search"}],
            "messages": [{"role": "user", "content": prompt}]
        }
        data = _call_claude_api(payload)
        if data is None:
            log_cb("[AI] Не удалось получить ответ от API")
            return []

        # Извлекаем текстовый ответ из контента
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")

        # Чистим от markdown если есть
        text = re.sub(r"```json\s*", "", text)
        text = re.sub(r"```\s*", "", text)
        text = text.strip()

        # Пробуем найти JSON массив
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            candidates = json.loads(match.group())
            log_cb(f"[AI] Найдено {len(candidates)} кандидатов из интернета")
            return candidates
        else:
            log_cb("[AI] Не удалось разобрать JSON из ответа")
            return []

    except Exception as e:
        log_cb(f"[AI] Ошибка поиска: {e}")
        return []


def generate_candidates_via_api(domain: str, failed: List[Dict],
                                log_cb: Callable[[str], None]) -> List[Dict]:
    """
    Генерирует новые кандидаты через Claude, учитывая уже провалившиеся.
    """
    log_cb(f"[AI] Генерация новых стратегий для {domain}…")

    failed_desc = json.dumps([
        {"desync": p.get("desync", []), "multiprofile": p.get("multiprofile", False)}
        for p in failed
    ], ensure_ascii=False)

    service_name = _guess_service_name(domain)

    prompt = f"""You are an expert on zapret2 anti-DPI software (https://github.com/bol-van/zapret2).

I'm trying to bypass DPI blocking for: **{domain}** ({service_name}).

These strategies already FAILED (do not suggest them again):
{failed_desc}

Generate 5 NEW diverse --lua-desync strategy profiles for zapret2 that might work.
Consider different approaches:
- Different fake packet fooling (tcp_md5, ip_autottl, tcp_seq, badseq)
- Different split positions (midsld, 1, method+2, endhost-1)
- wssize+syndata combination
- multisplit with seqovl
- oob technique
- QUIC/UDP bypass if the service uses it

Return ONLY a JSON array with no preamble, no markdown. Each element:
{{
  "name": "descriptive name",
  "source": "generated",
  "filter_tcp": "443",
  "filter_udp": "",
  "filter_l7": "tls",
  "out_range": "-d10",
  "desync": ["arg1", "arg2"],
  "multiprofile": false,
  "profiles": []
}}"""

    try:
        payload = {
            "model": CLAUDE_MODEL,
            "max_tokens": 1500,
            "messages": [{"role": "user", "content": prompt}]
        }
        data = _call_claude_api(payload)
        if data is None:
            return []

        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")

        text = re.sub(r"```json\s*", "", text)
        text = re.sub(r"```\s*", "", text)
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            candidates = json.loads(match.group())
            log_cb(f"[AI] Сгенерировано {len(candidates)} новых кандидатов")
            return candidates
        return []
    except Exception as e:
        log_cb(f"[AI] Ошибка генерации: {e}")
        return []


def mix_strategies(profiles: List[Dict], log_cb: Callable[[str], None]) -> List[Dict]:
    """
    Создаёт смешанные профили из набора успешных/перспективных стратегий.
    Возвращает список новых мульти-профилей.
    """
    if len(profiles) < 2:
        return []

    log_cb("[AI] Создание смешанных профилей…")
    mixed = []

    # 1. Простые пары (один HTTPS + один HTTP)
    https_profiles = [p for p in profiles if "443" in str(p.get("filter_tcp",""))]
    http_profiles  = [p for p in profiles if "80" in str(p.get("filter_tcp",""))]

    if https_profiles:
        best_https = https_profiles[0]
        http_part = {
            "filter_tcp": "80", "filter_l7": "http", "out_range": "-d10",
            "desync": ["fake:blob=fake_default_http:ip_autottl=-2,3-20:tcp_md5",
                       "fakedsplit:ip_autottl=-2,3-20:tcp_md5"]
        }
        quic_part = {
            "filter_udp": "443", "filter_l7": "quic",
            "desync": ["fake:blob=fake_default_quic:repeats=11"]
        }
        https_part = {
            "filter_tcp": best_https.get("filter_tcp", "443"),
            "filter_l7":  best_https.get("filter_l7", "tls"),
            "out_range":  best_https.get("out_range", "-d10"),
            "desync":     best_https.get("desync", []),
        }
        mixed.append({
            "name": f"Микс: {best_https.get('name','HTTPS')} + HTTP + QUIC",
            "source": "mixed",
            "multiprofile": True,
            "profiles": [http_part, https_part, quic_part]
        })

    # 2. Комбинация двух лучших HTTPS стратегий как мульти-профиль с хостлистами
    if len(https_profiles) >= 2:
        a, b = https_profiles[0], https_profiles[1]
        mixed.append({
            "name": f"Микс: {a.get('name','Стр.1')} || {b.get('name','Стр.2')}",
            "source": "mixed",
            "multiprofile": True,
            "profiles": [
                {"filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
                 "desync": a.get("desync", [])},
                {"filter_tcp": "443", "filter_l7": "tls", "out_range": "-d10",
                 "desync": b.get("desync", [])},
            ]
        })

    log_cb(f"[AI] Создано {len(mixed)} смешанных профилей")
    return mixed

# ─── Основной класс подбора ───────────────────────────────────────────────────

class StrategyFinder:
    """
    Оркестрирует процесс подбора стратегий.
    Вызывается из TUI; все события сообщаются через callback-и.
    """

    def __init__(self,
                 domain: str,
                 zapret_cfg: dict,
                 log_cb: Callable[[str], None],
                 progress_cb: Callable[[str, int, int], None],  # (msg, current, total)
                 found_cb: Callable[[dict], None],   # вызывается при успехе
                 done_cb: Callable[[bool], None],    # True=нашли, False=не нашли
                 ):
        self.domain = domain.strip().lstrip("https://").lstrip("http://").split("/")[0]
        self.cfg    = zapret_cfg
        self.log    = log_cb
        self.progress = progress_cb
        self.found  = found_cb
        self.done   = done_cb
        self._stop  = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._kill_proc()

    def _kill_proc(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None

    def _run(self):
        domain = self.domain
        self.log(f"[AI] Начало подбора стратегии для: {domain}")

        # ── Шаг 0: базовая проверка без zapret ──────────────────────────────
        self.progress("Базовая проверка доступности…", 0, 100)
        ok_base, detail = check_connectivity(domain)
        if ok_base:
            self.log(f"[AI] {domain} уже доступен без zapret ({detail})!")
            self.done(True)
            return
        self.log(f"[AI] Базовая проверка: недоступен ({detail})")

        # ── Шаг 1: поиск готовых решений через Claude+web_search ────────────
        self.progress("Поиск готовых решений в интернете…", 5, 100)
        internet_candidates = []
        if not self._stop.is_set():
            internet_candidates = search_solutions_via_api(domain, self.log)

        # ── Шаг 2: встроенная матрица кандидатов ────────────────────────────
        builtin = []
        for tcp, l7, rng, ds in CANDIDATE_MATRIX:
            builtin.append({
                "name": f"builtin:{ds[0][:30]}",
                "source": "builtin",
                "filter_tcp": tcp, "filter_l7": l7,
                "out_range": rng, "desync": ds,
                "multiprofile": False, "profiles": [],
            })
        # Добавляем мульти-порт
        mp = dict(MULTIPORT_CANDIDATE)
        mp["name"] = "Полный комплект HTTP+HTTPS+QUIC"
        mp["source"] = "builtin"
        builtin.append(mp)

        all_candidates = internet_candidates + builtin
        failed = []
        total = len(all_candidates) + 15  # +15 резерв для AI генерации

        # ── Шаг 3: перебор кандидатов ───────────────────────────────────────
        idx = 0
        for candidate in all_candidates:
            if self._stop.is_set():
                break
            idx += 1
            name = candidate.get("name", f"#{idx}")
            self.progress(f"Тест [{idx}/{len(all_candidates)}]: {name[:40]}", idx, total)
            self.log(f"[AI] Тест стратегии: {name}")

            ok, detail = self._test_strategy(candidate, domain)
            if ok:
                self.log(f"[AI] ✓ УСПЕХ: {name} ({detail})")
                candidate["name"] = f"{_guess_service_name(domain)}: {name}"
                self.found(candidate)
                # Создаём миксы
                mixed = mix_strategies([candidate] + [c for c in failed if c.get("_partial")], self.log)
                for m in mixed:
                    self.found(m)
                self.done(True)
                return
            else:
                self.log(f"[AI] ✗ Неудача: {name} ({detail})")
                failed.append(candidate)

        # ── Шаг 4: AI генерирует новые стратегии ────────────────────────────
        if not self._stop.is_set():
            self.progress("AI генерирует новые стратегии…", idx, total)
            ai_candidates = generate_candidates_via_api(domain, failed, self.log)

            for candidate in ai_candidates:
                if self._stop.is_set():
                    break
                idx += 1
                name = candidate.get("name", f"ai-#{idx}")
                self.progress(f"AI тест [{idx}]: {name[:40]}", idx, total)
                self.log(f"[AI] Тест AI стратегии: {name}")

                ok, detail = self._test_strategy(candidate, domain)
                if ok:
                    self.log(f"[AI] ✓ УСПЕХ (AI): {name} ({detail})")
                    candidate["name"] = f"{_guess_service_name(domain)} [AI]: {name}"
                    self.found(candidate)
                    mixed = mix_strategies([candidate], self.log)
                    for m in mixed:
                        self.found(m)
                    self.done(True)
                    return
                else:
                    self.log(f"[AI] ✗ AI неудача: {name} ({detail})")
                    failed.append(candidate)

        # ── Шаг 5: попытка миксов из частично-рабочего ──────────────────────
        if not self._stop.is_set() and len(failed) >= 2:
            self.progress("Создание комбинированных профилей…", idx, total)
            mixed = mix_strategies(failed[:4], self.log)
            for candidate in mixed:
                if self._stop.is_set():
                    break
                idx += 1
                name = candidate.get("name", "mixed")
                self.progress(f"Микс тест: {name[:40]}", idx, total)
                ok, detail = self._test_strategy(candidate, domain)
                if ok:
                    self.log(f"[AI] ✓ УСПЕХ (Микс): {name}")
                    candidate["name"] = f"{_guess_service_name(domain)} [Микс]"
                    self.found(candidate)
                    self.done(True)
                    return

        self.log(f"[AI] Автоматический подбор не нашёл рабочей стратегии для {domain}")
        self.done(False)

    def _test_strategy(self, profile: dict, domain: str,
                       test_timeout: int = 12) -> Tuple[bool, str]:
        """
        Запускает nfqws2 с профилем на ~10 секунд и проверяет curl.
        """
        from zapret2_tui_helpers import build_cmdline, find_binary
        binary = find_binary(self.cfg)
        if not binary:
            return False, "бинарник не найден"

        # Добавляем хостлист для конкретного домена
        test_profile = dict(profile)
        # Записываем временный hostlist
        hl_path = f"/tmp/zapret2_test_{int(time.time())}.txt"
        try:
            with open(hl_path, "w") as f:
                f.write(domain + "\n")
            test_profile["hostlist"] = hl_path
        except Exception:
            pass

        try:
            cmd = build_cmdline(self.cfg, test_profile)
        except Exception as e:
            return False, f"ошибка сборки cmd: {e}"

        # Запускаем процесс
        self.log(f"[AI]   → {' '.join(cmd[:5])}…")
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return False, "бинарник недоступен"
        except PermissionError:
            return False, "нет прав (нужен root)"
        except Exception as e:
            return False, str(e)

        # Даём время на старт
        time.sleep(2)

        if self._proc.poll() is not None:
            return False, f"процесс упал (код {self._proc.returncode})"

        # Проверяем доступность
        ok, detail = wait_for_connectivity(domain, retries=2, delay=1.5)

        # Останавливаем
        self._kill_proc()

        # Чистим хостлист
        try:
            os.unlink(hl_path)
        except Exception:
            pass

        return ok, detail


# ─── Вспомогательные ─────────────────────────────────────────────────────────

def _guess_service_name(domain: str) -> str:
    """Угадывает человекочитаемое название сервиса по домену."""
    known = {
        "instagram.com": "Instagram", "www.instagram.com": "Instagram",
        "facebook.com": "Facebook",   "www.facebook.com": "Facebook",
        "twitter.com": "Twitter/X",   "x.com": "Twitter/X",
        "youtube.com": "YouTube",     "www.youtube.com": "YouTube",
        "tiktok.com": "TikTok",       "www.tiktok.com": "TikTok",
        "telegram.org": "Telegram",   "t.me": "Telegram",
        "discord.com": "Discord",     "discordapp.com": "Discord",
        "linkedin.com": "LinkedIn",   "reddit.com": "Reddit",
        "twitch.tv": "Twitch",        "spotify.com": "Spotify",
        "netflix.com": "Netflix",     "whatsapp.com": "WhatsApp",
        "zoom.us": "Zoom",
    }
    return known.get(domain.lower(), domain.split(".")[0].capitalize())


def _call_claude_api(payload: dict) -> Optional[dict]:
    """Вызывает Anthropic API. API key из env ANTHROPIC_API_KEY."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None

    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            CLAUDE_API_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "web-search-2025-03-05",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return None
    except Exception:
        return None
