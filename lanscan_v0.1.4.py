#!/usr/bin/env python3
"""
LAN Proxy Scanner v0.1.4 - 區域網路住宅代理節點偵測工具
掃描區域網路活躍主機，識別設備資訊與代理風險評估
"""

VERSION = "0.1.4"

import select
import errno as _errno
import socket
import struct
import ipaddress
import threading
import time
import sys
import json
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
    conf.verb = 0
except BaseException:
    SCAPY_AVAILABLE = False

DEBUG     = False
SOURCE_IP = None   # 掃描時 TCP socket 綁定的來源 IP

CYAN  = "\033[36m"
RESET = "\033[0m"
BOLD  = "\033[1m"
LEVEL_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[92m",
}

# EHOSTUNREACH 在 macOS=65, Linux=113
_EHOSTUNREACH = getattr(_errno, "EHOSTUNREACH", 113)
_ENETUNREACH  = getattr(_errno, "ENETUNREACH",  101)
_UNREACHABLE  = {_EHOSTUNREACH, _ENETUNREACH}


def dbg(msg):
    if DEBUG:
        print(f"  {CYAN}[DBG] {msg}{RESET}", flush=True)


def color(text, level):
    return f"{LEVEL_COLOR.get(level, '')}{text}{RESET}"


def _errno_name(code):
    for name in dir(_errno):
        if name.startswith("E") and getattr(_errno, name) == code:
            return name
    return str(code)


# ─── Port 定義 ────────────────────────────────────────────────────────────────

PROXY_PORTS = {
    1080:  ("SOCKS4/5 Proxy",     "CRITICAL", "住宅代理最常用 SOCKS 代理埠"),
    3128:  ("Squid HTTP Proxy",   "CRITICAL", "Squid 開放代理，常見住宅代理組件"),
    8080:  ("HTTP Proxy/Alt",     "HIGH",     "HTTP 代理替代埠，住宅代理常用"),
    8118:  ("Privoxy",            "HIGH",     "Privoxy 隱私代理服務"),
    8888:  ("HTTP Proxy/Alt",     "HIGH",     "常見代理替代埠"),
    9050:  ("Tor SOCKS",          "CRITICAL", "Tor 網路代理，高度可疑"),
    9051:  ("Tor Control",        "CRITICAL", "Tor 控制埠"),
    9999:  ("Proxy/Backdoor",     "HIGH",     "可疑代理或後門埠"),
    1081:  ("SOCKS Proxy Alt",    "HIGH",     "SOCKS 代理替代埠"),
    7777:  ("Proxy/Trojan",       "HIGH",     "可疑代理服務埠"),
    8123:  ("Polipo Proxy",       "HIGH",     "Polipo 代理服務"),
    3333:  ("Proxy/Mining",       "MEDIUM",   "代理或挖礦相關埠"),
    8008:  ("HTTP Alt",           "MEDIUM",   "HTTP 替代埠，可能為代理"),
    8443:  ("HTTPS Alt",          "MEDIUM",   "HTTPS 替代埠"),
}

VPN_PORTS = {
    1194:  ("OpenVPN UDP/TCP",    "HIGH",     "OpenVPN，可能做為 VPN 代理節點"),
    1723:  ("PPTP VPN",           "HIGH",     "PPTP VPN 協定"),
    500:   ("IKE/IPSec",          "MEDIUM",   "IPSec VPN 金鑰交換"),
    4500:  ("IPSec NAT-T",        "MEDIUM",   "IPSec NAT 穿透"),
    51820: ("WireGuard",          "HIGH",     "WireGuard VPN"),
    1701:  ("L2TP",               "MEDIUM",   "L2TP VPN 協定"),
    1149:  ("OpenVPN Alt",        "HIGH",     "OpenVPN 替代埠"),
    443:   ("HTTPS/VPN",          "LOW",      "標準 HTTPS，但也常用於 VPN 偽裝"),
    80:    ("HTTP",               "LOW",      "標準 HTTP"),
}

COMMON_PORTS = {
    21:    ("FTP",                "LOW",      ""),
    22:    ("SSH",                "LOW",      ""),
    23:    ("Telnet",             "MEDIUM",   "Telnet 明文傳輸，安全風險"),
    25:    ("SMTP",               "LOW",      ""),
    53:    ("DNS",                "LOW",      ""),
    110:   ("POP3",               "LOW",      ""),
    143:   ("IMAP",               "LOW",      ""),
    445:   ("SMB",                "MEDIUM",   "SMB 檔案共享，注意勒索軟體風險"),
    3306:  ("MySQL",              "MEDIUM",   "資料庫對外開放"),
    5432:  ("PostgreSQL",         "MEDIUM",   "資料庫對外開放"),
    6379:  ("Redis",              "HIGH",     "Redis 無認證常被利用"),
    27017: ("MongoDB",            "HIGH",     "MongoDB 常被掃描利用"),
    5900:  ("VNC",                "MEDIUM",   "遠端桌面"),
    3389:  ("RDP",                "MEDIUM",   "Windows 遠端桌面"),
    8883:  ("MQTT TLS",           "LOW",      "IoT MQTT"),
    1883:  ("MQTT",               "MEDIUM",   "IoT MQTT 無加密"),
    5555:  ("ADB/Android",        "HIGH",     "Android Debug Bridge，可能遭濫用"),
    2323:  ("Telnet Alt",         "HIGH",     "Telnet 替代埠，Mirai 殭屍網路常用"),
    6881:  ("BitTorrent",         "LOW",      "P2P 傳輸"),
}

ALL_SCAN_PORTS = {**PROXY_PORTS, **VPN_PORTS, **COMMON_PORTS}
RISK_WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 2}


# ─── 網路工具（跨平台：Linux / macOS）────────────────────────────────────────

def _local_ip_udp():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            dbg(f"UDP trick local IP: {ip}")
            return ip
    except Exception as e:
        dbg(f"UDP trick failed: {e}")
        return None


def get_default_interface():
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        dbg(f"ip route: {r.stdout.strip()!r}")
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                dbg(f"Linux iface: {iface}")
                return iface
    except Exception as e:
        dbg(f"ip route failed: {e}")

    try:
        r = subprocess.run(["route", "-n", "get", "default"],
                           capture_output=True, text=True, timeout=5)
        dbg(f"route -n get default: {r.stdout.strip()!r}")
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                iface = line.split(":")[-1].strip()
                dbg(f"macOS iface: {iface}")
                return iface
    except Exception as e:
        dbg(f"route -n get default failed: {e}")
    return None


def _iface_ip_mask(iface):
    try:
        r = subprocess.run(["ifconfig", iface],
                           capture_output=True, text=True, timeout=5)
        dbg(f"ifconfig {iface}: {r.stdout.strip()}")
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line.startswith("inet ") or (len(line.split()) > 1 and ":" in line.split()[1]):
                continue
            parts = line.split()
            ip = parts[1]
            if "netmask" in parts:
                idx = parts.index("netmask")
                raw = parts[idx + 1]
                mask = (socket.inet_ntoa(struct.pack(">I", int(raw, 16)))
                        if raw.startswith("0x") else raw)
                dbg(f"ifconfig parsed: ip={ip} mask={mask}")
                return ip, mask
    except Exception as e:
        dbg(f"ifconfig failed: {e}")

    try:
        r = subprocess.run(["ip", "addr", "show", iface],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "/" in line:
                ip, pfx = line.split()[1].split("/")
                mask_int = (0xFFFFFFFF << (32 - int(pfx))) & 0xFFFFFFFF
                mask = socket.inet_ntoa(struct.pack(">I", mask_int))
                return ip, mask
    except Exception as e:
        dbg(f"ip addr failed: {e}")
    return None, None


def _find_iface_for_ip(ip_str):
    """從 ifconfig 輸出找到擁有指定 IP 的介面名稱"""
    try:
        r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        current_iface = None
        for line in r.stdout.splitlines():
            if not line.startswith((" ", "\t")):
                current_iface = line.split(":")[0].split()[0]
            elif ip_str in line and "inet " in line:
                dbg(f"_find_iface_for_ip({ip_str}) -> {current_iface}")
                return current_iface
    except Exception as e:
        dbg(f"_find_iface_for_ip failed: {e}")
    return None


def get_local_network():
    dbg("=== 偵測本地網段 ===")
    iface = get_default_interface()
    if iface:
        ip, mask = _iface_ip_mask(iface)
        if ip and mask:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            dbg(f"Result: {network} via {iface}")
            return str(network), ip, iface

    local_ip = _local_ip_udp()
    if local_ip:
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        dbg(f"Fallback: {network} (assumed /24)")
        return str(network), local_ip, iface or "auto"
    return None, None, None


def find_source_ip_for_network(network_cidr):
    """
    找到本機在 network_cidr 網段上的 IP，用於 TCP socket 綁定。
    優先用 UDP connect trick；失敗時改解析 ifconfig 找同網段介面。
    """
    target_net = ipaddress.IPv4Network(network_cidr, strict=False)

    # 方法 1：UDP trick（OS 根據路由表選擇來源 IP）
    first_host = str(next(target_net.hosts()))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((first_host, 1))
            src = s.getsockname()[0]
            if src != "0.0.0.0":
                dbg(f"UDP trick source IP for {network_cidr}: {src}")
                return src
    except OSError as e:
        dbg(f"UDP trick for {network_cidr} failed: errno={e.errno} ({_errno_name(e.errno)})")

    # 方法 2：掃描 ifconfig 找在同網段的介面 IP
    try:
        r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        current_iface = "?"
        for line in r.stdout.splitlines():
            if not line.startswith((" ", "\t")):
                current_iface = line.split(":")[0].split()[0]
                continue
            parts = line.strip().split()
            if not parts or parts[0] != "inet" or len(parts) < 2:
                continue
            ip_str = parts[1]
            if ":" in ip_str:  # IPv6
                continue
            # 嘗試取 netmask 算出 prefix
            try:
                if "netmask" in parts:
                    idx = parts.index("netmask")
                    raw = parts[idx + 1]
                    if raw.startswith("0x"):
                        prefix = bin(int(raw, 16)).count("1")
                    else:
                        prefix = bin(struct.unpack(">I", socket.inet_aton(raw))[0]).count("1")
                    iface_net = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
                    if ipaddress.ip_address(ip_str) in target_net or target_net.overlaps(iface_net):
                        dbg(f"ifconfig found source IP {ip_str} on {current_iface} for {network_cidr}")
                        return ip_str
                else:
                    # 沒有 netmask，直接檢查 IP 是否在目標網段
                    if ipaddress.ip_address(ip_str) in target_net:
                        dbg(f"ifconfig found source IP {ip_str} on {current_iface}")
                        return ip_str
            except Exception:
                continue
    except Exception as e:
        dbg(f"ifconfig scan failed: {e}")

    return None


def check_route_to_network(network_cidr):
    """
    簡單驗證是否能路由到目標網段（使用 SOURCE_IP 綁定若已設定）。
    回傳 (reachable: bool, source_ip: str | None, warning_msg: str | None)
    """
    target_net = ipaddress.IPv4Network(network_cidr, strict=False)
    first_host = str(next(target_net.hosts()))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            if SOURCE_IP:
                s.bind((SOURCE_IP, 0))
            s.connect((first_host, 1))
            src = s.getsockname()[0]
            if src == "0.0.0.0":
                return False, None, "UDP trick 回傳 0.0.0.0，路由可能不正確"
            return True, src, None
    except OSError as e:
        if e.errno in _UNREACHABLE:
            return False, None, (
                f"EHOSTUNREACH/ENETUNREACH (errno={e.errno})：OS 路由表找不到到 {network_cidr} 的路徑。\n"
                f"  常見原因：\n"
                f"    1. 您的主機不在 {network_cidr} 網段（請執行 ifconfig | grep inet 確認）\n"
                f"    2. VPN 正在執行中，把 10.0.0.0/8 流量導向 VPN tunnel\n"
                f"    3. 需要手動新增路由：sudo route -n add -net {network_cidr} <gateway_ip>\n"
                f"  解決方式：使用 --source-ip 指定本機在該網段的 IP"
            )
        return False, None, f"OSError errno={e.errno} ({_errno_name(e.errno)})"


# ─── 主機發現 ─────────────────────────────────────────────────────────────────

def arp_scan(network_cidr, timeout=3):
    if not SCAPY_AVAILABLE:
        return ping_scan(network_cidr)
    print(f"  [*] ARP 掃描 {network_cidr} ...")
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        result, _ = srp(packet, timeout=timeout, verbose=False)
    except (PermissionError, OSError, Exception) as e:
        if any(k in str(e).lower() for k in ("permission", "root", "bpf")):
            print("  [!] ARP 掃描需要 root 權限，改用 Ping 掃描")
        else:
            print(f"  [!] ARP 掃描失敗 ({e})，改用 Ping 掃描")
        return ping_scan(network_cidr)
    hosts = []
    for _, rcv in result:
        hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc})
    return hosts


def ping_scan(network_cidr, max_workers=100):
    print(f"  [*] Ping 掃描 {network_cidr} ...")
    network = ipaddress.IPv4Network(network_cidr, strict=False)
    hosts = []
    lock = threading.Lock()

    def check_host(ip_str):
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip_str],
                                capture_output=True, timeout=3)
            if r.returncode == 0:
                with lock:
                    hosts.append({"ip": ip_str, "mac": "N/A"})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for f in as_completed([executor.submit(check_host, str(ip))
                                for ip in network.hosts()]):
            f.result()
    return hosts


# ─── 主機識別 ─────────────────────────────────────────────────────────────────

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_mac_vendor(mac, cache={}):
    if mac in ("N/A", "ff:ff:ff:ff:ff:ff", ""):
        return ""
    if mac in cache:
        return cache[mac]
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    try:
        r = subprocess.run(["grep", "-i", oui, "/usr/share/ieee-data/oui.txt"],
                           capture_output=True, text=True, timeout=2)
        if r.stdout:
            vendor = r.stdout.split("\t")[-1].strip()
            cache[mac] = vendor
            return vendor
    except Exception:
        pass
    if REQUESTS_AVAILABLE:
        try:
            r = requests.get(f"https://api.macvendors.com/{oui}",
                             timeout=3, headers={"User-Agent": f"lanscan/{VERSION}"})
            if r.status_code == 200:
                vendor = r.text.strip()
                cache[mac] = vendor
                return vendor
        except Exception:
            pass
    cache[mac] = ""
    return ""


# ─── 埠口掃描 ─────────────────────────────────────────────────────────────────

class HostUnreachable(Exception):
    """EHOSTUNREACH / ENETUNREACH：OS 無法路由到此主機"""
    pass


def scan_port(ip, port, timeout=1.5):
    """
    blocking settimeout + connect，綁定 SOURCE_IP（若有設定）。
    回傳 (is_open: bool, banner: str, outcome: str)
    outcome 值: 'open' | 'timeout' | 'refused' | 'error'
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if SOURCE_IP:
            s.bind((SOURCE_IP, 0))
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = ""
        try:
            s.settimeout(0.5)
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(64).decode("utf-8", errors="ignore").split("\n")[0].strip()
        except Exception:
            pass
        return True, banner, "open"
    except (socket.timeout, TimeoutError):
        return False, "", "timeout"
    except ConnectionRefusedError:
        return False, "", "refused"
    except OSError as e:
        if e.errno in _UNREACHABLE:
            raise HostUnreachable(f"{ip} errno={e.errno} ({_errno_name(e.errno)})")
        if e.errno == _errno.EINPROGRESS:
            dbg(f":{port} EINPROGRESS fallback to select")
            try:
                _, w, _ = select.select([], [s], [], timeout)
                if w:
                    so_err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if so_err == 0:
                        return True, "", "open"
                    if so_err == _errno.ECONNREFUSED:
                        return False, "", "refused"
                return False, "", "timeout"
            except Exception as se:
                dbg(f":{port} select fallback failed: {se}")
        dbg(f":{port} OSError errno={e.errno} ({_errno_name(e.errno)})")
        return False, "", "error"
    except Exception as e:
        dbg(f":{port} unexpected: {type(e).__name__}: {e}")
        return False, "", "error"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def _run_self_test():
    """
    開啟本地 TCP 伺服器，呼叫 scan_port() 驗證掃描引擎是否正常運作。
    回傳 (success: bool, detail: str)
    """
    global SOURCE_IP
    saved_source = SOURCE_IP
    SOURCE_IP = None  # 本地測試不需綁定來源 IP
    srv = None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        test_port = srv.getsockname()[1]

        def _accept_one():
            try:
                conn, _ = srv.accept()
                conn.close()
            except Exception:
                pass

        t = threading.Thread(target=_accept_one, daemon=True)
        t.start()

        ok, banner, _ = scan_port("127.0.0.1", test_port, timeout=2.0)
        t.join(timeout=1.0)
        detail = f"127.0.0.1:{test_port}"
        return ok, detail
    except Exception as e:
        return False, str(e)
    finally:
        SOURCE_IP = saved_source
        if srv:
            try:
                srv.close()
            except Exception:
                pass


def scan_ports(ip, ports, max_workers=50, timeout=1.5):
    """
    並行掃描，偵測到 EHOSTUNREACH 時立即中止並回傳 None（表示主機不可達）。
    同時追蹤每台主機的連線統計（timeout / refused / open）。
    """
    open_ports = {}
    unreachable = threading.Event()
    stats = {"timeout": 0, "refused": 0, "open": 0, "error": 0}
    stats_lock = threading.Lock()

    def _scan(port):
        if unreachable.is_set():
            return port, False, "", "skip"
        try:
            is_open, banner, outcome = scan_port(ip, port, timeout)
            return port, is_open, banner, outcome
        except HostUnreachable:
            unreachable.set()
            return port, False, "", "unreachable"

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan, port): port for port in ports}
        for future in as_completed(futures):
            port, is_open, banner, outcome = future.result()
            with stats_lock:
                if is_open:
                    stats["open"] += 1
                    open_ports[port] = banner
                elif outcome == "timeout":
                    stats["timeout"] += 1
                elif outcome == "refused":
                    stats["refused"] += 1
                elif outcome == "skip":
                    pass
                else:
                    stats["error"] += 1

    if unreachable.is_set():
        return None, stats
    return open_ports, stats


# ─── 單埠三方法診斷工具 ───────────────────────────────────────────────────────

def test_single_port(host, port, timeout=3.0):
    SEP = "─" * 55
    print(f"\n{SEP}")
    print(f"{BOLD}  單埠診斷: {host}:{port}{RESET}")
    print(f"{SEP}")

    # 方法 1: blocking settimeout + connect
    print(f"\n  方法 1 │ blocking settimeout({timeout}s) + connect()")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if SOURCE_IP:
            print(f"  設定   │ 綁定來源 IP: {SOURCE_IP}")
            s.bind((SOURCE_IP, 0))
        s.settimeout(timeout)
        t0 = time.monotonic()
        try:
            s.connect((host, port))
            elapsed = time.monotonic() - t0
            print(f"  結果   │ \033[92mOPEN\033[0m  (連線成功，耗時 {elapsed:.3f}s)")
        except socket.timeout:
            elapsed = time.monotonic() - t0
            print(f"  結果   │ CLOSED/FILTERED  (timeout 後 {elapsed:.3f}s)")
        except ConnectionRefusedError:
            elapsed = time.monotonic() - t0
            print(f"  結果   │ CLOSED  (Connection refused，耗時 {elapsed:.3f}s)")
        except OSError as e:
            elapsed = time.monotonic() - t0
            print(f"  結果   │ ERROR  OSError errno={e.errno} ({_errno_name(e.errno)})  {elapsed:.3f}s")
            if e.errno in _UNREACHABLE:
                print(f"  ⚠ 路由問題：OS 找不到到 {host} 的路徑。")
                print(f"    請確認本機有 {host} 所在網段的 IP，或使用 --source-ip 指定。")
    except Exception as e:
        print(f"  結果   │ EXCEPTION  {type(e).__name__}: {e}")
    finally:
        if s:
            try: s.close()
            except: pass

    # 方法 2: non-blocking + select
    print(f"\n  方法 2 │ non-blocking connect_ex() + select({timeout}s)")
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if SOURCE_IP:
            s.bind((SOURCE_IP, 0))
        s.setblocking(False)
        err = s.connect_ex((host, port))
        print(f"  步驟   │ connect_ex() = {err} ({_errno_name(err)})")
        if err == 0:
            print(f"  結果   │ \033[92mOPEN\033[0m  (即時連線成功)")
        elif err in (_errno.EINPROGRESS, _errno.EWOULDBLOCK,
                     getattr(_errno, "WSAEWOULDBLOCK", 10035)):
            t0 = time.monotonic()
            try:
                _, w_set, _ = select.select([], [s], [], timeout)
                elapsed = time.monotonic() - t0
                print(f"  步驟   │ select() writable={bool(w_set)}  耗時 {elapsed:.3f}s")
                if w_set:
                    so_err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    print(f"  步驟   │ SO_ERROR = {so_err} ({_errno_name(so_err) if so_err else 'OK'})")
                    open_str = "\033[92mOPEN\033[0m" if so_err == 0 else "CLOSED"
                    print(f"  結果   │ {open_str}")
                else:
                    print(f"  結果   │ CLOSED/FILTERED  (select timeout)")
            except Exception as se:
                print(f"  步驟   │ select() 例外: {type(se).__name__}: {se}")
        elif err in _UNREACHABLE:
            print(f"  結果   │ EHOSTUNREACH (路由問題，見方法 1 說明)")
        else:
            print(f"  結果   │ CLOSED  (立即錯誤)")
    except Exception as e:
        print(f"  結果   │ EXCEPTION  {type(e).__name__}: {e}")
    finally:
        if s:
            try: s.close()
            except: pass

    # 方法 3: nc
    print(f"\n  方法 3 │ nc -zv -w {int(timeout)} {host} {port}")
    try:
        r = subprocess.run(
            ["nc", "-zv", "-w", str(int(timeout)), host, str(port)],
            capture_output=True, text=True, timeout=timeout + 2
        )
        if r.stdout.strip(): print(f"  stdout │ {r.stdout.strip()}")
        if r.stderr.strip(): print(f"  stderr │ {r.stderr.strip()}")
        result_str = "\033[92mOPEN\033[0m" if r.returncode == 0 else "CLOSED"
        print(f"  結果   │ {result_str}  (returncode={r.returncode})")
    except FileNotFoundError:
        print(f"  結果   │ SKIP  (nc not found)")
    except Exception as e:
        print(f"  結果   │ EXCEPTION  {type(e).__name__}: {e}")

    # 方法 4: curl（HTTP 埠）
    if port in (80, 443, 8080, 8443, 8888):
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        print(f"\n  方法 4 │ curl {url}")
        try:
            r = subprocess.run(
                ["curl", "-sk", "--max-time", str(int(timeout)),
                 "-o", "/dev/null", "-w", "%{http_code}", url],
                capture_output=True, text=True, timeout=timeout + 2
            )
            code = r.stdout.strip()
            if code and code != "000":
                print(f"  結果   │ \033[92mOPEN\033[0m  HTTP status={code}")
            else:
                print(f"  結果   │ CLOSED/FILTERED  (code={code!r})")
        except Exception as e:
            print(f"  結果   │ EXCEPTION  {type(e).__name__}: {e}")

    print(f"\n{SEP}")


# ─── 風險評估 ─────────────────────────────────────────────────────────────────

def assess_risk(open_ports):
    score = 0
    findings = []
    for port, banner in open_ports.items():
        info = ALL_SCAN_PORTS.get(port)
        if not info:
            score += 5
            findings.append({"port": port, "service": "Unknown",
                              "level": "MEDIUM", "note": "未知服務埠口"})
            continue
        svc, sev, note = info
        score += RISK_WEIGHTS.get(sev, 0)
        findings.append({"port": port, "service": svc, "level": sev,
                          "note": note, "banner": banner})

    proxy_open = [p for p in open_ports if p in PROXY_PORTS]
    vpn_open   = [p for p in open_ports if p in VPN_PORTS and p not in (80, 443)]
    if len(proxy_open) >= 2:
        score += 30
        findings.append({"port": 0, "service": "複合代理風險", "level": "CRITICAL",
                          "note": f"偵測到多個代理埠同時開放: {proxy_open}"})
    if proxy_open and vpn_open:
        score += 20
        findings.append({"port": 0, "service": "代理+VPN 複合", "level": "CRITICAL",
                          "note": f"代理埠 {proxy_open} 與 VPN 埠 {vpn_open} 同時開放"})

    if score >= 60:   level = "CRITICAL"
    elif score >= 35: level = "HIGH"
    elif score >= 15: level = "MEDIUM"
    else:             level = "LOW"
    return {"score": score, "level": level, "findings": findings}


# ─── 報告輸出 ─────────────────────────────────────────────────────────────────

def print_host_report(host_data, index, total):
    ip         = host_data["ip"]
    mac        = host_data["mac"]
    hostname   = host_data.get("hostname", "")
    vendor     = host_data.get("vendor", "")
    risk       = host_data["risk"]
    open_ports = host_data["open_ports"]
    unreachable = host_data.get("unreachable", False)
    level      = risk["level"]
    score      = risk["score"]
    clr        = LEVEL_COLOR.get(level, "")

    print(f"\n{'─'*65}")
    print(f"{BOLD}[{index}/{total}] {ip}{RESET}  {clr}▶ {level} (分數: {score}){RESET}")
    print(f"  MAC      : {mac}")
    if vendor:      print(f"  廠商     : {vendor}")
    if hostname:    print(f"  主機名稱 : {hostname}")

    stats = host_data.get("stats", {})
    if unreachable:
        print(f"  \033[91m警告     : EHOSTUNREACH - TCP 無法到達（路由問題）\033[0m")
        print(f"             請確認本機 IP 在 {ip} 所在網段，或使用 --source-ip")
    elif open_ports:
        for p in sorted(open_ports):
            svc = ALL_SCAN_PORTS.get(p, ("Unknown", "", ""))[0]
            banner = open_ports[p]
            bstr = f"  [{banner}]" if banner else ""
            print(f"  開放     : {p}/{svc}{bstr}")
    else:
        to_cnt  = stats.get("timeout", 0)
        ref_cnt = stats.get("refused", 0)
        if to_cnt > 0 and ref_cnt == 0:
            print(f"  開放埠口 : (未偵測到，全部 {to_cnt} 埠 timeout → DROP 防火牆)")
        elif ref_cnt > 0:
            print(f"  開放埠口 : (未偵測到，{ref_cnt} 埠拒絕/{to_cnt} 埠 timeout)")
        else:
            print(f"  開放埠口 : (未偵測到)")

    if risk["findings"]:
        print(f"  風險評估 :")
        for f in risk["findings"]:
            pstr = f":{f['port']}" if f["port"] else ""
            note = f"  {f['note']}" if f["note"] else ""
            print(f"    {color(f['level'], f['level']):<20} {f['service']}{pstr}{note}")


def print_summary(results, scan_time, network, local_ip, all_timeout=False):
    print(f"\n{'═'*65}")
    print(f"{BOLD}掃描摘要{RESET}")
    print(f"{'═'*65}")
    print(f"  掃描網段   : {network}")
    print(f"  本機 IP    : {local_ip}")
    print(f"  掃描時間   : {scan_time:.1f} 秒")
    print(f"  發現主機數 : {len(results)}")

    unreachable_hosts = [h for h in results if h.get("unreachable")]
    if unreachable_hosts:
        print(f"\n  \033[91m⚠ EHOSTUNREACH 主機 ({len(unreachable_hosts)} 台)：TCP 連線被路由表阻擋\033[0m")
        for h in unreachable_hosts:
            print(f"    {h['ip']}")
        print(f"\n  解決方式：")
        print(f"    1. 確認本機有在目標網段的 IP (ifconfig | grep inet)")
        print(f"    2. 如有 VPN，請先暫時關閉或設定分流路由")
        print(f"    3. 使用 --source-ip <您的IP> 明確指定來源介面")
        print(f"    4. 添加路由：sudo route -n add -net {network} <gateway>")
        return

    if all_timeout and results:
        total_ports = sum(
            len(h.get("stats", {})) and
            (h["stats"].get("timeout", 0) + h["stats"].get("refused", 0) + h["stats"].get("open", 0))
            for h in results
        )
        print(f"\n  \033[93m⚠ 所有 TCP 連線均 Timeout（無任何 OPEN 或 Connection Refused）\033[0m")
        print(f"  \033[93m  掃描時間 {scan_time:.1f}s 符合「全部 timeout」特徵\033[0m")
        print(f"\n  可能原因分析：")
        print(f"    A. DROP 防火牆  ─ 遠端主機丟棄封包而非回應 RST（最常見）")
        print(f"       對比：若是 CLOSED 埠口，會立即收到 RST（Connection refused，< 1ms）")
        print(f"       Timeout 代表封包送出但沒有任何回應，通常是防火牆丟棄。")
        print(f"\n    B. 路由/介面問題  ─ 封包根本沒有送到正確的網路介面")
        print(f"       解決：sudo python3 lanscan_v{VERSION}.py --test-port <IP> <PORT>")
        print(f"             nc -zv -w 3 <IP> <PORT>   (若 nc 也 timeout，確認是防火牆)")
        print(f"\n    C. 來源 IP 綁定問題  ─ 封包送出介面不對（有多個 utun VPN 介面時）")
        print(f"       解決：--source-ip <您在 {network} 網段的 IP>")
        print(f"\n  建議下一步：")
        print(f"    1. 執行: nc -zv -w 3 10.0.0.1 80   # 測試路由器 HTTP")
        print(f"    2. 執行: nc -zv -w 3 10.0.0.1 22   # 測試 SSH")
        print(f"    3. 若 nc 也 timeout → 防火牆 DROP，掃描結果正確（無開放代理埠）")
        print(f"    4. 若 nc 能連通   → 掃描引擎問題，請回報 --debug 輸出")
        return

    critical = [h for h in results if h["risk"]["level"] == "CRITICAL"]
    high     = [h for h in results if h["risk"]["level"] == "HIGH"]
    medium   = [h for h in results if h["risk"]["level"] == "MEDIUM"]
    print()
    if critical:
        print(f"  {color('CRITICAL 風險主機', 'CRITICAL')} ({len(critical)} 台):")
        for h in critical:
            proxy_ports = [p for p in h["open_ports"] if p in PROXY_PORTS]
            vpn_ports   = [p for p in h["open_ports"] if p in VPN_PORTS and p not in (80, 443)]
            flags = []
            if proxy_ports: flags.append(f"代理埠:{proxy_ports}")
            if vpn_ports:   flags.append(f"VPN埠:{vpn_ports}")
            print(f"    ★ {h['ip']}  {' | '.join(flags)}")
    if high:
        print(f"  {color('HIGH 風險主機', 'HIGH')} ({len(high)} 台):")
        for h in high: print(f"    ! {h['ip']}  開放: {sorted(h['open_ports'].keys())}")
    if medium:
        print(f"  {color('MEDIUM 風險主機', 'MEDIUM')} ({len(medium)} 台):")
        for h in medium: print(f"    - {h['ip']}  開放: {sorted(h['open_ports'].keys())}")
    print()
    if critical:
        print(f"{color('  ⚠ 建議立即檢查 CRITICAL 等級主機！', 'CRITICAL')}")
    else:
        print(f"{color('  ✓ 未發現明顯住宅代理指標。', 'LOW')}")


def save_json_report(results, path, network, local_ip, scan_time):
    report = {
        "version":          VERSION,
        "scan_time":        datetime.now().isoformat(),
        "network":          network,
        "local_ip":         local_ip,
        "source_ip":        SOURCE_IP,
        "duration_seconds": round(scan_time, 2),
        "hosts":            results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n  [+] JSON 報告已儲存至 {path}")


# ─── 主程式 ───────────────────────────────────────────────────────────────────

def main():
    global DEBUG, SOURCE_IP

    parser = argparse.ArgumentParser(
        description=f"LAN Proxy Scanner v{VERSION} - 區域網路住宅代理節點偵測工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
版本: {VERSION}

範例:
  sudo python3 lanscan_v{VERSION}.py                        # 自動偵測網段
  sudo python3 lanscan_v{VERSION}.py -n 10.0.0.0/24         # 指定網段
  sudo python3 lanscan_v{VERSION}.py -n 10.0.0.0/24 --source-ip 10.0.0.5
       python3 lanscan_v{VERSION}.py --test-port 10.0.0.1 80
  sudo python3 lanscan_v{VERSION}.py --debug -n 10.0.0.0/24
  sudo python3 lanscan_v{VERSION}.py -o report.json
        """
    )
    parser.add_argument("-n", "--network",    help="指定掃描網段 (例: 192.168.1.0/24)")
    parser.add_argument("--source-ip",        help="TCP 掃描的來源 IP（本機在目標網段的 IP）")
    parser.add_argument("-t", "--timeout",    type=float, default=1.5, help="埠口掃描超時秒數 (預設 1.5)")
    parser.add_argument("-w", "--workers",    type=int,   default=50,  help="並行執行緒數 (預設 50)")
    parser.add_argument("-o", "--output",     help="輸出 JSON 報告路徑")
    parser.add_argument("--fast",             action="store_true", help="快速模式，只掃代理/VPN 關鍵埠")
    parser.add_argument("--arp-timeout",      type=int, default=3,  help="ARP 掃描超時秒數 (預設 3)")
    parser.add_argument("--debug",            action="store_true",  help="開啟除錯輸出")
    parser.add_argument("--test-port",        nargs=2, metavar=("HOST", "PORT"),
                        help="單埠三方法診斷，例: --test-port 10.0.0.1 80")
    args = parser.parse_args()

    DEBUG = args.debug
    if args.source_ip:
        SOURCE_IP = args.source_ip

    print(f"\n{'═'*65}")
    print(f"{BOLD}  LAN Proxy Scanner  ─  住宅代理節點偵測工具{RESET}")
    print(f"  版本     : {VERSION}")
    print(f"  Python   : {sys.version.split()[0]}  平台: {sys.platform}")
    print(f"{'═'*65}")
    print(f"  啟動時間 : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── 掃描引擎自我測試 ──
    print(f"  自我測試 : ", end="", flush=True)
    self_test_ok, self_test_detail = _run_self_test()
    if self_test_ok:
        print(f"\033[92mPASS\033[0m  (localhost TCP scan 正常: {self_test_detail})")
    else:
        print(f"\033[91mFAIL\033[0m  ({self_test_detail})")
        print(f"\n  \033[91m[!] 掃描引擎自我測試失敗！\033[0m")
        print(f"      scan_port() 無法連到本機 TCP server，代表掃描引擎本身有問題。")
        print(f"      可能原因：root 環境 socket 權限異常、Python 版本相容問題。")
        print(f"      請以 --debug 重新執行並回報輸出。繼續執行但結果可能不可靠。")
        print()

    # ── 單埠診斷模式 ──
    if args.test_port:
        host = args.test_port[0]
        try:
            port = int(args.test_port[1])
        except ValueError:
            print("[!] PORT 必須是數字"); sys.exit(1)
        test_single_port(host, port, timeout=3.0)
        sys.exit(0)

    # ── 決定掃描網段 ──
    if args.network:
        network_cidr = args.network
        local_ip     = "N/A"
        iface        = "N/A"
    else:
        if DEBUG:
            print("\n[DEBUG] 網路介面偵測")
        network_cidr, local_ip, iface = get_local_network()
        if not network_cidr:
            print("\n[!] 無法自動偵測網段，請使用 -n 參數指定")
            sys.exit(1)

    # ── 來源 IP 自動偵測（無論 -n 是否指定都執行）──
    if SOURCE_IP is None:
        auto_src = find_source_ip_for_network(network_cidr)
        if auto_src:
            SOURCE_IP = auto_src
            dbg(f"auto source IP: {SOURCE_IP}")
        else:
            print(f"\n  \033[93m[!] 無法自動偵測 {network_cidr} 的來源 IP\033[0m")
            print(f"      請執行: ifconfig | grep inet")
            print(f"      再使用: --source-ip <你的IP>")

    # 用 source IP 補全 local_ip 與 iface（當 -n 指定時 N/A）
    if SOURCE_IP and local_ip == "N/A":
        local_ip = SOURCE_IP
    if SOURCE_IP and iface == "N/A":
        iface = _find_iface_for_ip(SOURCE_IP) or "auto"

    # ── 路由可達性檢查 ──
    reachable, _, warn_msg = check_route_to_network(network_cidr)
    if not reachable:
        print(f"\n  \033[91m[!] 路由問題偵測到：\033[0m")
        for line in warn_msg.splitlines():
            print(f"  {line}")
        if SOURCE_IP:
            print(f"\n  [*] 將使用 source-ip={SOURCE_IP} 強制綁定，繼續嘗試...")
        else:
            print(f"\n  [*] 嘗試繼續掃描（可能仍會失敗）...")

    print(f"  網路介面 : {iface}")
    print(f"  本機 IP  : {local_ip}")
    if SOURCE_IP:
        print(f"  來源 IP  : {SOURCE_IP}  (TCP socket 綁定)")
    print(f"  掃描網段 : {network_cidr}")
    print(f"  埠口超時 : {args.timeout}s  執行緒: {args.workers}")

    if args.fast:
        ports_to_scan = list(PROXY_PORTS.keys()) + [p for p in VPN_PORTS if p not in (80, 443)]
        print(f"  掃描模式 : 快速（{len(ports_to_scan)} 個關鍵埠口）")
    else:
        ports_to_scan = list(ALL_SCAN_PORTS.keys())
        print(f"  掃描模式 : 完整（{len(ports_to_scan)} 個埠口）")

    start_time = time.time()

    # ── 主機發現 ──
    print(f"\n[1/3] 主機發現")
    hosts = arp_scan(network_cidr, timeout=args.arp_timeout)
    if not hosts:
        print("  [!] 未發現任何活躍主機"); sys.exit(0)
    print(f"  [+] 發現 {len(hosts)} 台活躍主機")

    # ── 主機識別 ──
    print(f"\n[2/3] 主機識別（DNS + MAC 廠商）")
    for host in hosts:
        host["hostname"] = get_hostname(host["ip"])
        host["vendor"]   = get_mac_vendor(host["mac"])
        name_str = host["hostname"] or host["vendor"] or ""
        print(f"  {host['ip']:<18} {host['mac']:<20} {name_str}")
        time.sleep(0.05)

    # ── 埠口掃描 ──
    print(f"\n[3/3] 埠口掃描 + 風險評估")
    results = []
    has_any_refused_or_open = False
    all_unreachable = True
    for i, host in enumerate(hosts, 1):
        ip = host["ip"]
        sys.stdout.write(f"  掃描 {ip} ({i}/{len(hosts)}) ...\r")
        sys.stdout.flush()
        result, stats = scan_ports(ip, ports_to_scan,
                                   max_workers=args.workers,
                                   timeout=args.timeout)
        if stats["refused"] > 0 or stats["open"] > 0:
            has_any_refused_or_open = True
        if result is None:
            # EHOSTUNREACH
            risk = {"score": 0, "level": "LOW", "findings": []}
            results.append({**host, "open_ports": {}, "risk": risk,
                            "unreachable": True, "stats": stats})
        else:
            all_unreachable = False
            risk = assess_risk(result)
            results.append({**host, "open_ports": result, "risk": risk,
                            "unreachable": False, "stats": stats})
    all_timeout = (not has_any_refused_or_open) and (not all_unreachable)

    print(f"  掃描完成{' '*40}")

    results.sort(key=lambda h: h["risk"]["score"], reverse=True)
    for i, host in enumerate(results, 1):
        print_host_report(host, i, len(results))

    scan_time = time.time() - start_time
    print_summary(results, scan_time, network_cidr, local_ip, all_timeout=all_timeout)

    if args.output:
        for h in results:
            h["open_ports"] = {str(k): v for k, v in h["open_ports"].items()}
        save_json_report(results, args.output, network_cidr, local_ip, scan_time)


if __name__ == "__main__":
    main()
