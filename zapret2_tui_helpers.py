"""zapret2_tui_helpers.py — переиспользуемые функции из zapret2-tui (build_cmdline, find_binary)"""
import os
import shlex
import glob
from typing import Optional, List

def find_binary(cfg: dict) -> Optional[str]:
    """
    Ищет бинарник nfqws2 по всем возможным путям.
    Поддерживает структуру zapret2: binaries/my/, nfq2/, binaries/.
    """
    import shutil
    zdir   = cfg.get("zapret_dir", "/opt/zapret2")
    binary = cfg.get("binary", "nfqws2")

    candidates = [
        # Явный путь если пользователь задал полный путь
        binary if os.path.isabs(binary) else None,
        # Корень zapret_dir
        os.path.join(zdir, binary),
        # nfq2/ — путь из systemd лога
        os.path.join(zdir, "nfq2", binary),
        # binaries/my/ — реальная структура на машине пользователя
        os.path.join(zdir, "binaries", "my", binary),
        # binaries/ напрямую
        os.path.join(zdir, "binaries", binary),
        # bin/
        os.path.join(zdir, "bin", binary),
    ]

    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c

    # Рекурсивный поиск в zapret_dir (ищем исполняемый файл с нужным именем)
    try:
        pattern = os.path.join(zdir, "**", binary)
        for found in glob.glob(pattern, recursive=True):
            if os.path.isfile(found) and os.access(found, os.X_OK):
                # Пропускаем docs/ — там могут быть примеры
                if "docs" not in found.split(os.sep):
                    return found
    except Exception:
        pass

    # PATH системы
    return shutil.which(binary)


def find_binary_auto(zapret_dir: str) -> Optional[str]:
    """
    Автоопределение: ищет любой nfqws2 в zapret_dir и возвращает
    путь + имя бинарника для сохранения в конфиг.
    Возвращает (full_path, relative_or_name) или (None, None).
    """
    for name in ("nfqws2", "winws2", "nfqws"):
        cfg = {"zapret_dir": zapret_dir, "binary": name}
        found = find_binary(cfg)
        if found:
            return found, name
    return None, None


def build_cmdline(cfg: dict, profile: dict, extra_flags: str = "") -> List[str]:
    binary     = find_binary(cfg) or cfg.get("binary", "nfqws2")
    zdir       = cfg.get("zapret_dir", "/opt/zapret2")
    lua_lib    = os.path.join(zdir, cfg.get("lua_lib",    "lua/zapret-lib.lua"))
    lua_antidpi= os.path.join(zdir, cfg.get("lua_antidpi","lua/zapret-antidpi.lua"))

    cmd = [binary, f"--qnum={cfg.get('qnum','200')}"]
    cmd += [f"--lua-init=@{lua_lib}", f"--lua-init=@{lua_antidpi}"]

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
        if p.get("out_range"): cmd.append(f"--out-range={p['out_range']}")
        if p.get("in_range"):  cmd.append(f"--in-range={p['in_range']}")
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
