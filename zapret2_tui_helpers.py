"""zapret2_tui_helpers.py — переиспользуемые функции из zapret2-tui (build_cmdline, find_binary)"""
import os
import shlex
from typing import Optional, List

def find_binary(cfg: dict) -> Optional[str]:
    import shutil
    candidates = [
        os.path.join(cfg.get("zapret_dir", "/opt/zapret2"), cfg.get("binary", "nfqws2")),
        os.path.join(cfg.get("zapret_dir", "/opt/zapret2"), "binaries", cfg.get("binary", "nfqws2")),
        cfg.get("binary", "nfqws2"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return shutil.which(cfg.get("binary", "nfqws2"))

def build_cmdline(cfg: dict, profile: dict, extra_flags: str = "") -> List[str]:
    binary = find_binary(cfg) or cfg.get("binary", "nfqws2")
    zdir = cfg.get("zapret_dir", "/opt/zapret2")
    lua_lib = os.path.join(zdir, cfg.get("lua_lib", "lua/zapret-lib.lua"))
    lua_antidpi = os.path.join(zdir, cfg.get("lua_antidpi", "lua/zapret-antidpi.lua"))
    cmd = [binary, f"--qnum={cfg.get('qnum','200')}"]
    cmd += [f"--lua-init=@{lua_lib}", f"--lua-init=@{lua_antidpi}"]
    for li in profile.get("lua_init", []):
        cmd.append(f"--lua-init={li}")
    for b in profile.get("blobs", []):
        cmd.append(f"--blob={b}")

    def add_block(p, is_last):
        if p.get("filter_tcp"):
            cmd.append(f"--filter-tcp={p['filter_tcp']}")
        if p.get("filter_udp"):
            cmd.append(f"--filter-udp={p['filter_udp']}")
        if p.get("filter_l7"):
            cmd.append(f"--filter-l7={p['filter_l7']}")
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
        if p.get("out_range"):
            cmd.append(f"--out-range={p['out_range']}")
        if p.get("in_range"):
            cmd.append(f"--in-range={p['in_range']}")
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
