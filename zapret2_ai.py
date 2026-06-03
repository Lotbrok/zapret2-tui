"""
zapret2_ai.py — AI-модуль подбора стратегий обхода для zapret2-tui

Поддерживает:
  - Claude (Anthropic) — с web_search инструментом для поиска в интернете
  - ChatGPT (OpenAI)   — gpt-4o и другие модели

Все ключи загружаются через zapret2_config.py (из .env файла).
"""

import json, os, re, subprocess, threading, time, urllib.request, urllib.error
from typing import List, Dict, Optional, Callable, Tuple
from zapret2_config import (
    get_api_key, get_model, get_active_provider, AI_PROVIDERS
)

# ─── Матрица встроенных кандидатов ───────────────────────────────────────────

BUILTIN_CANDIDATES = [
    ("443", "tls",  "-d10", ["fake:blob=fake_default_tls:tcp_md5:repeats=6",          "multidisorder:pos=midsld"]),
    ("443", "tls",  "-d10", ["fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6", "multidisorder:pos=midsld"]),
    ("443", "tls",  "-d10", ["fake:blob=fake_default_tls:tcp_md5:repeats=11:tls_mod=rnd,dupsid,sni=www.google.com", "multidisorder:pos=1,midsld"]),
    ("443", "tls",  "-d10", ["fake:blob=fake_default_tls:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5", "fakedsplit:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:tcp_md5"]),
    ("443", "tls",  "-d10", ["fake:blob=fake_default_tls:tcp_md5:repeats=6:tls_mod=rnd,rndsni,dupsid", "multisplit:pos=1:seqovl=5"]),
    ("443", "tls",  "-d10", ["wssize:wsize=1:scale=6", "syndata", "multisplit:pos=midsld"]),
    ("443", "tls",  "-d10", ["fake:blob=fake_default_tls:tcp_flags_unset=ack:tls_mod=rnd,rndsni,dupsid"]),
    ("443", "tls",  "-d10", ["fakedsplit:ip_autottl=-1,3-20:tcp_md5"]),
    ("443", "tls",  "-d10", ["multisplit:pos=1,midsld"]),
    ("80,443", "tls,http", "-d10", ["fake:blob=fake_default_tls:tcp_md5", "multidisorder:pos=midsld"]),
]

# ─── HTTP-клиент ─────────────────────────────────────────────────────────────

def _http_post(url, headers, payload, timeout=90):
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return {"_error": json.loads(e.read())}
        except Exception:
            return {"_error": str(e)}
    except Exception as e:
        return {"_error": str(e)}

# ─── Провайдеры ──────────────────────────────────────────────────────────────

def call_claude(cfg, messages, system="", use_web_search=False):
    key = get_api_key("claude", cfg)
    if not key:
        return None
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "anthropic-beta":    "web-search-2025-03-05",
    }
    payload = {"model": get_model("claude", cfg), "max_tokens": 2000, "messages": messages}
    if system:
        payload["system"] = system
    if use_web_search:
        payload["tools"] = [{"type": "web_search_20250305", "name": "web_search"}]
    data = _http_post(AI_PROVIDERS["claude"]["url"], headers, payload)
    if not data or "_error" in data:
        return None
    return "".join(b.get("text","") for b in data.get("content",[]) if b.get("type")=="text")


def call_openai(cfg, messages, system=""):
    key = get_api_key("openai", cfg)
    if not key:
        return None
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {key}",
    }
    full = []
    if system:
        full.append({"role": "system", "content": system})
    full.extend(messages)
    payload = {"model": get_model("openai", cfg), "max_tokens": 2000, "messages": full}
    data = _http_post(AI_PROVIDERS["openai"]["url"], headers, payload)
    if not data or "_error" in data:
        return None
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        return None


def call_ai(cfg, messages, system="", use_web_search=False):
    """Универсальный вызов — выбирает провайдера из настроек."""
    provider = cfg.get("ai_provider") or get_active_provider(cfg)
    if provider == "openai":
        sys_extra = "\nUse your knowledge of recent configurations and community solutions." if use_web_search else ""
        return call_openai(cfg, messages, system + sys_extra)
    else:
        return call_claude(cfg, messages, system, use_web_search)


def test_api_key(provider, cfg):
    """Проверяет что ключ рабочий."""
    try:
        if provider == "claude":
            result = call_claude(cfg, [{"role":"user","content":"Reply with just: OK"}])
        else:
            result = call_openai(cfg, [{"role":"user","content":"Reply with just: OK"}])
        if result:
            return True, "Ключ работает ✓"
        return False, "Нет ответа от API"
    except Exception as e:
        return False, str(e)

# ─── Вспомогательные ─────────────────────────────────────────────────────────

def guess_service(domain):
    known = {
        "instagram.com":"Instagram","facebook.com":"Facebook",
        "twitter.com":"Twitter/X","x.com":"Twitter/X",
        "youtube.com":"YouTube","tiktok.com":"TikTok",
        "telegram.org":"Telegram","t.me":"Telegram",
        "discord.com":"Discord","linkedin.com":"LinkedIn",
        "reddit.com":"Reddit","twitch.tv":"Twitch",
        "spotify.com":"Spotify","netflix.com":"Netflix","whatsapp.com":"WhatsApp",
    }
    d = domain.lower().lstrip("www.")
    return known.get(d, known.get(domain.lower(), domain.split(".")[0].capitalize()))

def normalize_domain(raw):
    raw = raw.strip()
    raw = re.sub(r"^https?://", "", raw)
    return raw.split("/")[0].split("?")[0]

def parse_json_candidates(text):
    text = re.sub(r"```json\s*","", text)
    text = re.sub(r"```\s*","", text)
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    return None

def check_url(domain, timeout=8):
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

# ─── Промпты ─────────────────────────────────────────────────────────────────

SYSTEM_EXPERT = """You are an expert on zapret2 anti-DPI software (github.com/bol-van/zapret2).
You know all --lua-desync arguments: fake, fakedsplit, multisplit, multidisorder,
syndata, wssize, oob, pktmod, tcpseg, drop, luaexec.
Fooling params: tcp_md5, ip_autottl, ip6_autottl, tcp_seq, tcp_ack, badseq, datanoack.
Return ONLY valid JSON arrays when asked. No markdown, no explanation."""

def _search_prompt(domain, svc):
    return f"""Search for existing working zapret / nfqws bypass configurations for:
**{domain}** ({svc})

Look on: ntc.party, habr.com, 4pda.to, GitHub issues/gists.

Return ONLY a JSON array, no text before/after:
[{{"name":"short name","source":"URL","filter_tcp":"443","filter_udp":"","filter_l7":"tls","out_range":"-d10","desync":["arg1","arg2"],"multiprofile":false,"profiles":[]}}]"""

def _generate_prompt(domain, svc, failed_json):
    return f"""Generate new zapret2 bypass strategies for: **{domain}** ({svc})

Already FAILED (do not repeat):
{failed_json}

Try: oob:data=0x00 / multisplit:pos=2:seqovl=5 / fake with tcp_flags_unset=ack /
fakedsplit with tcp_ack=-66000 / wssize+syndata / pktmod:ip_ttl=1 / QUIC+TLS combo

Return ONLY JSON array:
[{{"name":"..","source":"generated","filter_tcp":"443","filter_udp":"","filter_l7":"tls","out_range":"-d10","desync":["arg"],"multiprofile":false,"profiles":[]}}]"""

# ─── StrategyFinder ───────────────────────────────────────────────────────────

class StrategyFinder:
    def __init__(self, domain, cfg, log_cb, progress_cb, found_cb, done_cb):
        self.domain   = normalize_domain(domain)
        self.cfg      = cfg
        self.log      = log_cb
        self.progress = progress_cb
        self.found    = found_cb
        self.done     = done_cb
        self._stop    = threading.Event()
        self._proc    = None
        self._thread  = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._kill()

    def _kill(self):
        if self._proc and self._proc.poll() is None:
            try: self._proc.terminate(); self._proc.wait(2)
            except Exception:
                try: self._proc.kill()
                except Exception: pass
        self._proc = None

    def _provider_name(self):
        p = self.cfg.get("ai_provider") or get_active_provider(self.cfg)
        return AI_PROVIDERS.get(p, {}).get("name", p)

    def search_internet(self):
        svc = guess_service(self.domain)
        provider = self.cfg.get("ai_provider") or get_active_provider(self.cfg)
        self.log(f"[AI/{self._provider_name()}] Ищу решения для {svc}…")
        msg = [{"role":"user","content":_search_prompt(self.domain, svc)}]
        text = call_ai(self.cfg, msg, SYSTEM_EXPERT, use_web_search=(provider=="claude"))
        if not text:
            self.log(f"[AI] Нет ответа от {self._provider_name()}")
            return []
        result = parse_json_candidates(text)
        if result:
            self.log(f"[AI] Получено {len(result)} вариантов")
            return result
        self.log("[AI] Не удалось разобрать JSON из ответа")
        return []

    def generate_new(self, failed):
        svc = guess_service(self.domain)
        self.log(f"[AI/{self._provider_name()}] Генерирую новые стратегии…")
        failed_json = json.dumps([
            {"desync": p.get("desync",[]), "mp": p.get("multiprofile",False)}
            for p in failed[:8]
        ], ensure_ascii=False)
        msg = [{"role":"user","content":_generate_prompt(self.domain, svc, failed_json)}]
        text = call_ai(self.cfg, msg, SYSTEM_EXPERT)
        if not text:
            return []
        result = parse_json_candidates(text)
        if result:
            self.log(f"[AI] Сгенерировано {len(result)} вариантов")
            return result
        return []

    def _test(self, profile):
        from zapret2_tui_helpers import build_cmdline, find_binary
        binary = find_binary(self.cfg)
        if not binary:
            return False, "бинарник не найден"
        hl = f"/tmp/z2test_{int(time.time())}.txt"
        try:
            with open(hl,"w") as f: f.write(self.domain + "\n")
            p2 = dict(profile); p2["hostlist"] = hl
            cmd = build_cmdline(self.cfg, p2)
        except Exception as e:
            return False, str(e)
        self.log(f"[AI]   → {' '.join(cmd[:5])}…")
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except PermissionError: return False, "нет прав root"
        except FileNotFoundError: return False, "бинарник недоступен"
        except Exception as e: return False, str(e)

        time.sleep(2.5)
        if self._proc.poll() is not None:
            code = self._proc.returncode
            self._kill()
            try: os.unlink(hl)
            except: pass
            return False, f"процесс упал (код {code})"

        ok, detail = False, "timeout"
        for _ in range(3):
            if self._stop.is_set(): break
            ok, detail = check_url(self.domain)
            if ok: break
            time.sleep(1.5)

        self._kill()
        try: os.unlink(hl)
        except: pass
        return ok, detail

    def make_mixes(self, pool):
        if not pool: return []
        mixes = []
        https_p = next((p for p in pool if "443" in str(p.get("filter_tcp",""))), None)
        if https_p:
            mixes.append({
                "name": f"Микс: {https_p.get('name','HTTPS')[:20]} + HTTP + QUIC",
                "source":"mixed","multiprofile":True,
                "profiles":[
                    {"filter_tcp":"80","filter_l7":"http","out_range":"-d10",
                     "desync":["fake:blob=fake_default_http:ip_autottl=-2,3-20:tcp_md5",
                               "fakedsplit:ip_autottl=-2,3-20:tcp_md5"]},
                    {"filter_tcp":https_p.get("filter_tcp","443"),
                     "filter_l7":https_p.get("filter_l7","tls"),
                     "out_range":https_p.get("out_range","-d10"),
                     "desync":https_p.get("desync",[])},
                    {"filter_udp":"443","filter_l7":"quic",
                     "desync":["fake:blob=fake_default_quic:repeats=11"]},
                ]
            })
        https_all = [p for p in pool if "443" in str(p.get("filter_tcp",""))]
        if len(https_all) >= 2:
            a, b = https_all[0], https_all[1]
            mixes.append({
                "name": f"Микс: {a.get('name','')[:15]} || {b.get('name','')[:15]}",
                "source":"mixed","multiprofile":True,
                "profiles":[
                    {"filter_tcp":"443","filter_l7":"tls","out_range":"-d10","desync":a.get("desync",[])},
                    {"filter_tcp":"443","filter_l7":"tls","out_range":"-d10","desync":b.get("desync",[])},
                ]
            })
        return mixes

    def _run(self):
        domain = self.domain
        svc = guess_service(domain)
        self.log(f"[AI] ══════════════════════════")
        self.log(f"[AI] Провайдер: {self._provider_name()}")
        self.log(f"[AI] Цель: {domain} ({svc})")
        self.log(f"[AI] ══════════════════════════")

        self.progress("Базовая проверка…", 0, 100)
        ok, detail = check_url(domain)
        if ok:
            self.log(f"[AI] {domain} уже доступен без zapret ({detail})")
            self.done(True); return
        self.log(f"[AI] Без zapret: недоступен ({detail})")

        provider = self.cfg.get("ai_provider") or get_active_provider(self.cfg)
        has_key = bool(get_api_key(provider, self.cfg))
        internet = []
        if has_key and not self._stop.is_set():
            self.progress("Поиск решений через AI…", 5, 100)
            internet = self.search_internet()

        builtin = [{
            "name": f"builtin-{i+1}: {ds[0][:25]}",
            "source":"builtin",
            "filter_tcp":tcp,"filter_udp":"","filter_l7":l7,
            "out_range":rng,"desync":list(ds),"multiprofile":False,"profiles":[]
        } for i,(tcp,l7,rng,ds) in enumerate(BUILTIN_CANDIDATES)]
        builtin.append({
            "name":"builtin-full: HTTP+HTTPS+QUIC","source":"builtin","multiprofile":True,
            "profiles":[
                {"filter_tcp":"80","filter_l7":"http","out_range":"-d10",
                 "desync":["fake:blob=fake_default_http:ip_autottl=-2,3-20:tcp_md5","fakedsplit:ip_autottl=-2,3-20:tcp_md5"]},
                {"filter_tcp":"443","filter_l7":"tls","out_range":"-d10",
                 "desync":["fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6","multidisorder:pos=midsld"]},
                {"filter_udp":"443","filter_l7":"quic",
                 "desync":["fake:blob=fake_default_quic:repeats=11"]},
            ]
        })

        all_cands = internet + builtin
        failed = []
        total = len(all_cands) + 10

        for i, cand in enumerate(all_cands):
            if self._stop.is_set(): break
            name = cand.get("name", f"#{i+1}")
            src  = cand.get("source","?")
            self.progress(f"[{i+1}/{len(all_cands)}] {src}: {name[:35]}", i+1, total)
            self.log(f"[AI] Тест [{i+1}]: {name}")
            ok, detail = self._test(cand)
            if ok:
                self.log(f"[AI] ✓ УСПЕХ: {name} ({detail})")
                cand["name"] = f"{svc}: {src}: {name}"
                self.found(cand)
                for m in self.make_mixes([cand]): self.found(m)
                self.done(True); return
            else:
                self.log(f"[AI] ✗ {name}: {detail}")
                failed.append(cand)

        if has_key and not self._stop.is_set():
            self.progress("AI генерирует новые стратегии…", len(all_cands)+1, total)
            for i, cand in enumerate(self.generate_new(failed)):
                if self._stop.is_set(): break
                name = cand.get("name", f"ai-{i+1}")
                self.progress(f"AI тест: {name[:35]}", len(all_cands)+i+2, total)
                self.log(f"[AI] AI тест: {name}")
                ok, detail = self._test(cand)
                if ok:
                    self.log(f"[AI] ✓ УСПЕХ (AI): {name}")
                    cand["name"] = f"{svc} [AI]: {name}"
                    self.found(cand)
                    for m in self.make_mixes([cand]): self.found(m)
                    self.done(True); return
                else:
                    self.log(f"[AI] ✗ AI: {name}: {detail}")
                    failed.append(cand)

        if not self._stop.is_set() and len(failed) >= 2:
            self.progress("Тестирую комбинированные профили…", total-2, total)
            for cand in self.make_mixes(failed[:4]):
                if self._stop.is_set(): break
                self.log(f"[AI] Микс тест: {cand.get('name','mix')}")
                ok, detail = self._test(cand)
                if ok:
                    self.log(f"[AI] ✓ УСПЕХ (Микс): {cand.get('name')}")
                    cand["name"] = f"{svc} [Микс]"
                    self.found(cand)
                    self.done(True); return

        self.log(f"[AI] Стратегия для {domain} не найдена")
        self.done(False)
