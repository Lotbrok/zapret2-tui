"""zapret2_tui_helpers.py — переиспользуемые функции из zapret2-tui"""
import os
import shlex
import glob
from typing import Optional, List, Tuple


def find_binary(cfg: dict) -> Optional[str]:
    """
    Ищет бинарник nfqws2.
    cfg["binary"] может быть именем ("nfqws2") или полным путём ("/opt/zapret2/nfq2/nfqws2").
    """
    import shutil
    zdir   = cfg.get("zapret_dir", "/opt/zapret2")
    binary = cfg.get("binary", "nfqws2")

    # Случай 1: binary — уже полный путь
    if os.path.isabs(binary) and os.path.isfile(binary):
        return binary

    # Случай 2: имя файла — ищем по всем известным путям
    name = os.path.basename(binary)  # на случай если путь частичный
    candidates = [
        os.path.join(zdir, "nfq2",         name),   # /opt/zapret2/nfq2/nfqws2
        os.path.join(zdir, "binaries","my", name),   # /opt/zapret2/binaries/my/nfqws2
        os.path.join(zdir, "binaries",      name),   # /opt/zapret2/binaries/nfqws2
        os.path.join(zdir,                  name),   # /opt/zapret2/nfqws2
        os.path.join(zdir, "bin",           name),   # /opt/zapret2/bin/nfqws2
        "/usr/local/bin/" + name,
        "/usr/bin/" + name,
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    # Случай 3: рекурсивный glob (медленнее, но надёжно)
    try:
        for found in sorted(glob.glob(
                os.path.join(zdir, "**", name), recursive=True)):
            parts = found.split(os.sep)
            if "docs" not in parts and os.path.isfile(found):
                return found
    except Exception:
        pass

    # Случай 4: PATH системы
    return shutil.which(name)


def find_binary_auto(zapret_dir: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Автопоиск бинарника в zapret_dir.
    Возвращает (full_path, full_path) — оба значения одинаковы,
    чтобы cfg["binary"] = full_path и find_binary() сразу его нашёл.
    """
    for name in ("nfqws2", "winws2", "nfqws"):
        cfg = {"zapret_dir": zapret_dir, "binary": name}
        found = find_binary(cfg)
        if found:
            return found, found  # возвращаем полный путь в обоих полях
    return None, None


def build_cmdline(cfg: dict, profile: dict, extra_flags: str = "") -> List[str]:
    binary      = find_binary(cfg) or cfg.get("binary", "nfqws2")
    zdir        = cfg.get("zapret_dir", "/opt/zapret2")
    lua_lib     = os.path.join(zdir, cfg.get("lua_lib",     "lua/zapret-lib.lua"))
    lua_antidpi = os.path.join(zdir, cfg.get("lua_antidpi", "lua/zapret-antidpi.lua"))

    cmd = [binary,
           f"--qnum={cfg.get('qnum','200')}",
           f"--lua-init=@{lua_lib}",
           f"--lua-init=@{lua_antidpi}"]

    for li in profile.get("lua_init", []):
        cmd.append(f"--lua-init={li}")
    for b in profile.get("blobs", []):
        cmd.append(f"--blob={b}")

    def add_block(p, is_last):
        if p.get("filter_tcp"):  cmd.append(f"--filter-tcp={p['filter_tcp']}")
        if p.get("filter_udp"):  cmd.append(f"--filter-udp={p['filter_udp']}")
        if p.get("filter_l7"):   cmd.append(f"--filter-l7={p['filter_l7']}")
        if p.get("hostlist"):
            hl = p["hostlist"]
            if not os.path.isabs(hl):
                hl = os.path.join(zdir, hl)
            cmd.append(f"--hostlist={hl}")
        if p.get("hostlist_exclude"):
            he = p["hostlist_exclude"]
            if not os.path.isabs(he):
                he = os.path.join(zdir, he)
            cmd.append(f"--hostlist-exclude={he}")
        if p.get("out_range"):  cmd.append(f"--out-range={p['out_range']}")
        if p.get("in_range"):   cmd.append(f"--in-range={p['in_range']}")
        for payload in p.get("payloads", []):
            cmd.append(f"--payload={payload}")
        for ds in p.get("desync", []):
            cmd.append(f"--lua-desync={ds}")
        if not is_last:
            cmd.append("--new")

    if profile.get("multiprofile"):
        sub = profile["profiles"]
        for i, p in enumerate(sub):
            add_block(p, i == len(sub) - 1)
    else:
        add_block(profile, True)

    if extra_flags:
        cmd += shlex.split(extra_flags)
    return cmd
