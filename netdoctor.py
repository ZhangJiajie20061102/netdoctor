#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netdoctor —— Windows 网络环境诊断

检查几件最容易配错、又最难自己发现的事：
  1. 系统代理是否还开着（很多游戏客户端会因此连不上）
  2. 虚拟网卡（TUN）的 MTU 是不是被写成了 9000
  3. 有没有残留的安全软件驱动与服务
  4. 有没有残留的安全软件进程
  5. hosts 文件里有没有堆积奇怪条目

定位说明：这是一个网络与系统配置的检查工具，只读取公开的系统设置，
不读取、不注入、不修改任何第三方程序的内存或进程，也不针对任何特定游戏。

用法：
    python netdoctor.py              检查并输出报告
    python netdoctor.py --json       输出机器可读的 JSON
    python netdoctor.py --fix        修复能自动处理的问题（需要管理员权限）
    python netdoctor.py --fix proxy  只修系统代理
"""

import argparse
import ctypes
import json
import os
import re
import subprocess
import sys

VERSION = "1.0.0"

try:
    import winreg
except ImportError:  # pragma: no cover
    print("netdoctor 只能在 Windows 上运行。", file=sys.stderr)
    sys.exit(2)

# 虚拟网卡的名字里通常带这些词
TUN_HINTS = re.compile(
    r"(tun|tap|wintun|wireguard|^wg\d|xray|v2ray|sing[-_]?box|clash|mihomo|nekoray|proxy)",
    re.IGNORECASE,
)

# 常见的安全软件残留驱动（文件路径, 说明）
SUSPECT_DRIVERS = [
    (r"System32\drivers\360elam64.sys", "360 ELAM 引导驱动"),
    (r"System32\drivers\360box64.sys", "360 沙箱驱动"),
    (r"System32\drivers\360fsflt.sys", "360 文件过滤驱动"),
    (r"System32\drivers\360netmon.sys", "360 网络监控驱动"),
    (r"System32\drivers\qhkernel64.sys", "360 内核驱动"),
    (r"System32\drivers\qhactivex.sys", "360 主动防御驱动"),
]

# 服务名或显示名里出现这些词，基本可以断定是 360 系
SUSPECT_SERVICE_WORDS = ("360", "qihoo", "奇虎")

# 残留进程名（小写比较）
SUSPECT_PROCESSES = (
    "360tray", "360sd", "360safe", "zhudongfangyu", "360rp", "360se",
    "qqpctray", "qqpcrtp", "qmpersonalcenter",
)

HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")

# Windows 上别弹黑框
CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------

def run(cmd, timeout=20, encoding="utf-8"):
    """跑一条外部命令，失败返回 (1, "", 错误信息)。"""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        out = proc.stdout.decode(encoding, errors="replace").strip()
        err = proc.stderr.decode(encoding, errors="replace").strip()
        return proc.returncode, out, err
    except FileNotFoundError:
        return 1, "", f"找不到命令：{cmd[0]}"
    except subprocess.TimeoutExpired:
        return 1, "", f"命令超时：{' '.join(cmd[:2])}"
    except OSError as exc:
        return 1, "", str(exc)


def powershell(script, timeout=25):
    """跑一段 PowerShell 并把结果当 UTF-8 读回来。"""
    return run(
        [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script,
        ],
        timeout=timeout,
    )


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def result(key, title, level, detail, fixable=False, fix=None, data=None):
    return {
        "key": key,
        "title": title,
        "level": level,       # ok / warn / bad / info
        "detail": detail,
        "fixable": fixable,
        "fix": fix,
        "data": data or {},
    }


# --------------------------------------------------------------------------
# 检测项
# --------------------------------------------------------------------------

def check_proxy():
    """系统代理：开了代理再进游戏，很多客户端会直接连不上。"""
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            try:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                enabled = 0
            try:
                server = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                server = ""
            try:
                override = winreg.QueryValueEx(key, "ProxyOverride")[0]
            except FileNotFoundError:
                override = ""
    except OSError as exc:
        return result("proxy", "系统代理", "warn", f"读不到代理设置：{exc}")

    if enabled:
        target = server or "（未填地址）"
        return result(
            "proxy", "系统代理", "bad",
            f"已开启 → {target}",
            fixable=True, fix="proxy",
            data={"enabled": True, "server": server, "override": override},
        )
    return result(
        "proxy", "系统代理", "ok", "已关闭",
        data={"enabled": False, "server": server, "override": override},
    )


def _interfaces_via_powershell():
    code, out, _ = powershell(
        "Get-NetIPInterface -AddressFamily IPv4 | "
        "Select-Object InterfaceAlias,NlMtu,ConnectionState | ConvertTo-Json -Compress"
    )
    if code != 0 or not out:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        data = [data]
    items = []
    for row in data:
        alias = str(row.get("InterfaceAlias") or "").strip()
        mtu = row.get("NlMtu")
        if not alias or not isinstance(mtu, int):
            continue
        items.append({"name": alias, "mtu": mtu, "state": row.get("ConnectionState")})
    return items or None


def _interfaces_via_netsh():
    code, out, _ = run(["netsh", "interface", "ipv4", "show", "subinterfaces"], encoding="gbk")
    if code != 0 or not out:
        return None
    items = []
    pattern = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")
    for line in out.splitlines():
        m = pattern.match(line)
        if not m:
            continue
        items.append({"name": m.group(4), "mtu": int(m.group(1)), "state": None})
    return items or None


def list_interfaces():
    """列出 IPv4 接口与 MTU。优先 PowerShell，老系统回退 netsh。"""
    return _interfaces_via_powershell() or _interfaces_via_netsh() or []


def check_tun_mtu(interfaces=None):
    """虚拟网卡的 MTU。被写成 9000 会明显变卡。"""
    if interfaces is None:
        interfaces = list_interfaces()

    if not interfaces:
        return result("tun", "TUN 网卡 MTU", "info", "读不到网卡列表（可能权限不足）")

    tun = [i for i in interfaces if TUN_HINTS.search(i["name"])]
    if not tun:
        return result(
            "tun", "TUN 网卡 MTU", "info",
            "没发现虚拟网卡（可能用的是系统代理模式，或代理没开）",
            data={"interfaces": interfaces},
        )

    bad = [i for i in tun if i["mtu"] > 1500]
    if bad:
        names = "、".join(f"{i['name']} = {i['mtu']}" for i in bad)
        return result(
            "tun", "TUN 网卡 MTU", "bad",
            f"{names}（标准值 1500，巨帧会让流量变慢）",
            fixable=True, fix="mtu",
            data={"targets": [i["name"] for i in bad], "tun": tun},
        )

    names = "、".join(f"{i['name']} = {i['mtu']}" for i in tun)
    return result("tun", "TUN 网卡 MTU", "ok", names, data={"tun": tun})


def _scan_services():
    """扫注册表里的服务，找 360 系的残留。"""
    found = []
    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return found

    index = 0
    while True:
        try:
            name = winreg.EnumKey(root, index)
        except OSError:
            break
        index += 1
        display = ""
        image = ""
        try:
            with winreg.OpenKey(root, name) as key:
                for value_name in ("DisplayName", "ImagePath"):
                    try:
                        val = winreg.QueryValueEx(key, value_name)[0]
                    except FileNotFoundError:
                        continue
                    if value_name == "DisplayName":
                        display = str(val)
                    else:
                        image = str(val)
        except OSError:
            continue

        blob = f"{name} {display} {image}".lower()
        if any(word in blob for word in SUSPECT_SERVICE_WORDS):
            found.append({"name": name, "display": display or name, "image": image})

    winreg.CloseKey(root)
    return found


def check_services():
    """残留驱动与服务。只报告，不自动删除——删错驱动会让系统起不来。"""
    drivers = []
    for rel, desc in SUSPECT_DRIVERS:
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), rel)
        if os.path.exists(path):
            drivers.append({"path": path, "desc": desc})

    services = _scan_services()

    if not drivers and not services:
        return result("drivers", "残留驱动 / 服务", "ok", "没发现 360 系残留")

    parts = []
    if drivers:
        parts.append("驱动：" + "、".join(os.path.basename(d["path"]) for d in drivers))
    if services:
        names = [s["display"] for s in services][:4]
        more = "" if len(services) <= 4 else f" 等 {len(services)} 项"
        parts.append("服务：" + "、".join(names) + more)

    return result(
        "drivers", "残留驱动 / 服务", "warn",
        "；".join(parts) + "（建议在「服务」里禁用后重启，不要直接删驱动文件）",
        data={"drivers": drivers, "services": services},
    )


def check_processes():
    """残留进程。"""
    code, out, _ = powershell(
        "Get-Process | Select-Object -ExpandProperty ProcessName -ErrorAction SilentlyContinue | "
        "Where-Object { $_ -match '360|ZhuDongFangYu|QQPC|QM' } | Sort-Object -Unique"
    )
    if code != 0:
        return result("process", "残留进程", "info", "读不到进程列表")

    names = [line.strip() for line in out.splitlines() if line.strip()]
    hit = [n for n in names if n.lower() in SUSPECT_PROCESSES]
    if hit:
        return result(
            "process", "残留进程", "warn",
            "、".join(hit) + " 正在运行（关掉后再进游戏）",
            data={"processes": hit},
        )
    return result("process", "残留进程", "ok", "没有安全软件在后台运行")


def check_hosts():
    """hosts 文件。改过游戏的 hosts 常常忘了还原。"""
    if not os.path.exists(HOSTS_PATH):
        return result("hosts", "hosts 文件", "warn", "找不到 hosts 文件")

    try:
        with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return result("hosts", "hosts 文件", "warn", f"读不到：{exc}")

    entries = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)

    if len(entries) > 20:
        return result(
            "hosts", "hosts 文件", "warn",
            f"{len(entries)} 条有效记录，偏多（用过加速/防更新工具的话建议核对）",
            data={"count": len(entries), "sample": entries[:5]},
        )
    detail = f"{len(entries)} 条有效记录" if entries else "没有自定义记录"
    return result("hosts", "hosts 文件", "ok", detail, data={"count": len(entries)})


def run_checks():
    interfaces = list_interfaces()
    return [
        check_proxy(),
        check_tun_mtu(interfaces),
        check_services(),
        check_processes(),
        check_hosts(),
    ]


# --------------------------------------------------------------------------
# 修复
# --------------------------------------------------------------------------

def fix_proxy():
    """关闭系统代理，并通知系统刷新设置。"""
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    except OSError as exc:
        return False, f"写注册表失败：{exc}"

    try:
        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        pass  # 刷新失败不影响设置本身，下次登录也会生效

    return True, "系统代理已关闭"


def fix_mtu(names):
    """把虚拟网卡的 MTU 改回 1500。改的是运行中的适配器，需要管理员。"""
    if not is_admin():
        return False, "需要管理员权限：右键「以管理员身份运行」后重试"

    done, failed = [], []
    for name in names:
        code, out, err = run(
            ["netsh", "interface", "ipv4", "set", "subinterface", name, "mtu=1500", "store=persistent"],
            encoding="gbk",
        )
        if code == 0:
            done.append(name)
        else:
            failed.append(f"{name}（{(err or out).splitlines()[0] if (err or out) else '未知错误'}）")

    if failed:
        return False, "部分失败：" + "、".join(failed)
    return True, "MTU 已改回 1500：" + "、".join(done)


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------

LEVEL_STYLE = {
    "ok": ("✓", "32"),     # 绿
    "warn": ("!", "33"),   # 黄
    "bad": ("✗", "31"),    # 红
    "info": ("·", "90"),   # 灰
}


def enable_ansi():
    if os.name != "nt":
        return True
    try:
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
    except Exception:
        pass
    return False


def disp_width(text):
    """终端里的显示宽度：中文算两列，其余算一列。"""
    return sum(2 if ord(ch) > 0x2E80 else 1 for ch in text)


def print_report(results, color=True):
    width = 18
    print()
    print(f"netdoctor {VERSION} · Windows 网络环境诊断")
    print("─" * 62)
    for item in results:
        mark, code = LEVEL_STYLE.get(item["level"], ("·", "0"))
        if color:
            head = f"\033[{code}m[{mark}]\033[0m"
        else:
            head = f"[{mark}]"
        title = item["title"]
        pad = " " * max(1, width - disp_width(title))
        print(f"{head} {title}{pad}{item['detail']}")
    print("─" * 62)

    problems = [r for r in results if r["level"] in ("warn", "bad")]
    fixable = [r for r in problems if r["fixable"]]
    if not problems:
        print("全部正常。")
    else:
        serious = sum(1 for r in problems if r["level"] == "bad")
        print(f"发现 {len(problems)} 项需要关注" + (f"，其中 {serious} 项会直接影响联网" if serious else "") + "。")
        if fixable:
            print("可自动修复：" + "、".join(r["title"] for r in fixable))
            print("运行 python netdoctor.py --fix 处理（改 MTU 需要管理员权限）。")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="netdoctor",
        description="检查系统代理、虚拟网卡 MTU、残留驱动与进程等常见网络环境问题。",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--fix", nargs="*", metavar="项", help="修复问题：不带参数=全部，或指定 proxy / mtu")
    parser.add_argument("--no-color", action="store_true", help="不要彩色输出")
    parser.add_argument("--version", action="version", version=f"netdoctor {VERSION}")
    args = parser.parse_args(argv)

    results = run_checks()

    if args.json:
        print(json.dumps({"version": VERSION, "results": results}, ensure_ascii=False, indent=2))
        return 0 if all(r["level"] in ("ok", "info") for r in results) else 1

    color = not args.no_color and enable_ansi()
    print_report(results, color=color)

    if args.fix is None:
        return 0 if all(r["level"] in ("ok", "info") for r in results) else 1

    wanted = [w.lower() for w in args.fix] or ["proxy", "mtu"]
    changed = False

    if "proxy" in wanted:
        target = next((r for r in results if r["key"] == "proxy"), None)
        if target and target["level"] == "ok":
            print("系统代理本来就是关的，跳过。")
        else:
            ok, msg = fix_proxy()
            print(("✓ " if ok else "✗ ") + msg)
            changed = changed or ok

    if "mtu" in wanted:
        target = next((r for r in results if r["key"] == "tun"), None)
        if not target or not target["fixable"]:
            print("没有需要修的网卡 MTU，跳过。")
        else:
            names = target["data"].get("targets") or []
            ok, msg = fix_mtu(names)
            print(("✓ " if ok else "✗ ") + msg)
            changed = changed or ok

    if changed:
        print("\n修复完成。重新读一次状态：")
        return main(["--no-color"] if args.no_color else [])
    return 1


if __name__ == "__main__":
    sys.exit(main())
