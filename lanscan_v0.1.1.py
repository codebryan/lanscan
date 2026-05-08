#!/usr/bin/env python3
"""
LAN Proxy Scanner v0.1.1 - 區域網路住宅代理節點偵測工具
掃描區域網路活躍主機，識別設備資訊與代理風險評估
"""

VERSION = "0.1.1"

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

# 全域除錯旗標（由 --debug 設定）
DEBUG = False


def dbg(msg):
    if DEBUG:
        print(f"  \033[36m[DBG] {msg}\033[0m", flush=True)


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
    """UDP trick：連向外部 IP 取得本機出口 IP（不實際送出封包）"""
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
    """取得預設路由使用的網路介面名稱（Linux / macOS）"""
    # Linux: ip route show default
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        dbg(f"ip route stdout: {r.stdout.strip()!r}")
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                dbg(f"Linux default iface: {iface}")
                return iface
    except Exception as e:
        dbg(f"ip route failed: {e}")

    # macOS: route -n get default
    try:
        r = subprocess.run(["route", "-n", "get", "default"],
                           capture_output=True, text=True, timeout=5)
        dbg(f"route -n get default stdout: {r.stdout.strip()!r}")
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                iface = line.split(":")[-1].strip()
                dbg(f"macOS default iface: {iface}")
                return iface
    except Exception as e:
        dbg(f"route -n get default failed: {e}")

    return None


def _iface_ip_mask(iface):
    """從 ifconfig 或 ip addr 取得介面 IP 與子網路遮罩"""
    # ifconfig（Linux & macOS）
    try:
        r = subprocess.run(["ifconfig", iface],
                           capture_output=True, text=True, timeout=5)
        dbg(f"ifconfig {iface}:\n{r.stdout.strip()}")
        for line in r.stdout.splitlines():
            line = line.strip()
            # 跳過 IPv6（inet6）
            if not line.startswith("inet ") or (len(line.split()) > 1 and ":" in line.split()[1]):
                continue
            # Linux:  inet 10.0.0.5  netmask 255.255.255.0 ...
            # macOS:  inet 10.0.0.5 netmask 0xffffff00 broadcast ...
            parts = line.split()
            ip = parts[1]
            if "netmask" in parts:
                idx = parts.index("netmask")
                raw = parts[idx + 1]
                if raw.startswith("0x"):
                    mask = socket.inet_ntoa(struct.pack(">I", int(raw, 16)))
                else:
                    mask = raw
                dbg(f"ifconfig parsed: ip={ip} mask={mask}")
                return ip, mask
    except Exception as e:
        dbg(f"ifconfig {iface} failed: {e}")

    # ip addr show（Linux fallback）
    try:
        r = subprocess.run(["ip", "addr", "show", iface],
                           capture_output=True, text=True, timeout=5)
        dbg(f"ip addr show {iface}: {r.stdout.strip()!r}")
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "/" in line:
                addr_pfx = line.split()[1]
                ip, pfx = addr_pfx.split("/")
                mask_int = (0xFFFFFFFF << (32 - int(pfx))) & 0xFFFFFFFF
                mask = socket.inet_ntoa(struct.pack(">I", mask_int))
                dbg(f"ip addr parsed: ip={ip} mask={mask}")
                return ip, mask
    except Exception as e:
        dbg(f"ip addr show {iface} failed: {e}")

    return None, None


def get_local_network():
    """自動偵測本地網段（跨平台：Linux / macOS）"""
    dbg("=== 偵測本地網段 ===")
    iface = get_default_interface()
    if iface:
        ip, mask = _iface_ip_mask(iface)
        if ip and mask:
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            dbg(f"Network result: {network} via iface {iface}")
            return str(network), ip, iface

    # fallback：UDP trick + 假設 /24
    local_ip = _local_ip_udp()
    if local_ip:
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        dbg(f"Network fallback: {network} (assumed /24)")
        return str(network), local_ip, iface or "auto"

    return None, None, None


# ─── 主機發現 ─────────────────────────────────────────────────────────────────

def arp_scan(network_cidr, timeout=3):
    """ARP 掃描取得活躍主機清單（含 MAC 位址）"""
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
    """Ping 掃描（不需 root，無法取得 MAC）"""
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

def get_hostname(ip, timeout=1):
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


# ─── 埠口掃描（non-blocking + select，跨平台可靠）───────────────────────────

_debug_lock = threading.Lock()
_debug_first_host = None   # 只對第一台主機印除錯詳情


def _errno_name(code):
    """將 errno 數字轉成名稱（如 EINPROGRESS）"""
    for name in dir(_errno):
        if name.startswith("E") and getattr(_errno, name) == code:
            return name
    return str(code)


def scan_port(ip, port, timeout=1.0):
    """TCP connect 掃描（non-blocking + select）"""
    global _debug_first_host
    do_dbg = DEBUG and (ip == _debug_first_host)

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        err = s.connect_ex((ip, port))

        if do_dbg:
            with _debug_lock:
                print(f"  \033[36m[DBG] :{port}  connect_ex={err} ({_errno_name(err)})\033[0m",
                      flush=True)

        if err == 0:
            connected = True
        elif err in (_errno.EINPROGRESS, _errno.EWOULDBLOCK,
                     getattr(_errno, "WSAEWOULDBLOCK", 10035)):
            t0 = time.monotonic()
            _, writable, _ = select.select([], [s], [], timeout)
            elapsed = time.monotonic() - t0
            if writable:
                so_err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                connected = (so_err == 0)
                if do_dbg:
                    with _debug_lock:
                        print(f"  \033[36m[DBG] :{port}  select writable in {elapsed:.3f}s  "
                              f"SO_ERROR={so_err} ({_errno_name(so_err) if so_err else 'OK'})  "
                              f"-> {'OPEN' if connected else 'CLOSED'}\033[0m", flush=True)
            else:
                connected = False
                if do_dbg:
                    with _debug_lock:
                        print(f"  \033[36m[DBG] :{port}  select timeout after {elapsed:.3f}s  -> CLOSED\033[0m",
                              flush=True)
        else:
            connected = False
            if do_dbg:
                with _debug_lock:
                    print(f"  \033[36m[DBG] :{port}  immediate error -> CLOSED\033[0m", flush=True)

        if connected:
            banner = ""
            try:
                s.settimeout(0.5)
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(64).decode("utf-8", errors="ignore").split("\n")[0].strip()
            except Exception:
                pass
            return True, banner

    except Exception as e:
        if do_dbg:
            with _debug_lock:
                print(f"  \033[36m[DBG] :{port}  exception: {e}\033[0m", flush=True)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return False, ""


def scan_ports(ip, ports, max_workers=50, timeout=1.0):
    open_ports = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            is_open, banner = future.result()
            if is_open:
                open_ports[port] = banner
    return open_ports


# ─── 風險評估 ─────────────────────────────────────────────────────────────────

def assess_risk(open_ports):
    score = 0
    findings = []

    for port, banner in open_ports.items():
        info = ALL_SCAN_PORTS.get(port)
        if not info:
            score += 5
            findings.append({"port": port, "service": "Unknown", "level": "MEDIUM",
                              "note": "未知服務埠口"})
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
                          "note": f"代理埠 {proxy_open} 與 VPN 埠 {vpn_open} 同時開放，高度可疑"})

    if score >= 60:
        level = "CRITICAL"
    elif score >= 35:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "findings": findings}


# ─── 報告輸出 ─────────────────────────────────────────────────────────────────

LEVEL_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[92m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def color(text, level):
    return f"{LEVEL_COLOR.get(level, '')}{text}{RESET}"


def print_host_report(host_data, index, total):
    ip         = host_data["ip"]
    mac        = host_data["mac"]
    hostname   = host_data.get("hostname", "")
    vendor     = host_data.get("vendor", "")
    risk       = host_data["risk"]
    open_ports = host_data["open_ports"]
    level      = risk["level"]
    score      = risk["score"]
    clr        = LEVEL_COLOR.get(level, "")

    print(f"\n{'─'*65}")
    print(f"{BOLD}[{index}/{total}] {ip}{RESET}  {clr}▶ {level} (分數: {score}){RESET}")
    print(f"  MAC      : {mac}")
    if vendor:
        print(f"  廠商     : {vendor}")
    if hostname:
        print(f"  主機名稱 : {hostname}")

    if open_ports:
        for p in sorted(open_ports):
            svc = ALL_SCAN_PORTS.get(p, ("Unknown", "", ""))[0]
            banner = open_ports[p]
            banner_str = f"  [{banner}]" if banner else ""
            print(f"  開放     : {p}/{svc}{banner_str}")
    else:
        print(f"  開放埠口 : (未偵測到開放埠口)")

    if risk["findings"]:
        print(f"  風險評估 :")
        for f in risk["findings"]:
            port_str = f":{f['port']}" if f["port"] else ""
            note     = f"  {f['note']}" if f["note"] else ""
            print(f"    {color(f['level'], f['level']):<20} {f['service']}{port_str}{note}")


def print_summary(results, scan_time, network, local_ip):
    print(f"\n{'═'*65}")
    print(f"{BOLD}掃描摘要{RESET}")
    print(f"{'═'*65}")
    print(f"  掃描網段   : {network}")
    print(f"  本機 IP    : {local_ip}")
    print(f"  掃描時間   : {scan_time:.1f} 秒")
    print(f"  發現主機數 : {len(results)}")

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
        for h in high:
            print(f"    ! {h['ip']}  開放: {sorted(h['open_ports'].keys())}")

    if medium:
        print(f"  {color('MEDIUM 風險主機', 'MEDIUM')} ({len(medium)} 台):")
        for h in medium:
            print(f"    - {h['ip']}  開放: {sorted(h['open_ports'].keys())}")

    print()
    if critical:
        print(f"{color('  ⚠ 建議立即檢查 CRITICAL 等級主機！', 'CRITICAL')}")
        print("  請確認該主機是否安裝了不明的 VPN/代理程式，")
        print("  或是否有異常背景服務正在執行。")
    else:
        print(f"{color('  ✓ 未發現明顯住宅代理指標。', 'LOW')}")


def save_json_report(results, path, network, local_ip, scan_time):
    report = {
        "version":          VERSION,
        "scan_time":        datetime.now().isoformat(),
        "network":          network,
        "local_ip":         local_ip,
        "duration_seconds": round(scan_time, 2),
        "hosts":            results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n  [+] JSON 報告已儲存至 {path}")


# ─── 主程式 ───────────────────────────────────────────────────────────────────

def main():
    global DEBUG, _debug_first_host

    parser = argparse.ArgumentParser(
        description=f"LAN Proxy Scanner v{VERSION} - 區域網路住宅代理節點偵測工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
版本: {VERSION}

範例:
  sudo python3 lanscan_v{VERSION}.py                      # 自動偵測網段，完整掃描
  sudo python3 lanscan_v{VERSION}.py -n 192.168.1.0/24    # 指定網段
  sudo python3 lanscan_v{VERSION}.py --fast               # 快速模式（代理/VPN 關鍵埠）
  sudo python3 lanscan_v{VERSION}.py --debug              # 開啟除錯輸出
  sudo python3 lanscan_v{VERSION}.py -o report.json       # 輸出 JSON 報告
        """
    )
    parser.add_argument("-n", "--network",    help="指定掃描網段 (例: 192.168.1.0/24)")
    parser.add_argument("-t", "--timeout",    type=float, default=1.5,
                        help="埠口掃描超時秒數 (預設 1.5)")
    parser.add_argument("-w", "--workers",    type=int,   default=50,
                        help="並行掃描執行緒數 (預設 50)")
    parser.add_argument("-o", "--output",     help="輸出 JSON 報告路徑")
    parser.add_argument("--fast",             action="store_true",
                        help="快速模式，只掃代理/VPN 關鍵埠")
    parser.add_argument("--arp-timeout",      type=int, default=3,
                        help="ARP 掃描超時秒數 (預設 3)")
    parser.add_argument("--debug",            action="store_true",
                        help="開啟除錯輸出（顯示網路偵測細節與第一台主機的埠口掃描過程）")
    args = parser.parse_args()

    DEBUG = args.debug

    print(f"\n{'═'*65}")
    print(f"{BOLD}  LAN Proxy Scanner  ─  住宅代理節點偵測工具{RESET}")
    print(f"  版本     : {VERSION}")
    print(f"  Python   : {sys.version.split()[0]}  平台: {sys.platform}")
    print(f"{'═'*65}")
    print(f"  啟動時間 : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

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

    print(f"  網路介面 : {iface}")
    print(f"  本機 IP  : {local_ip}")
    print(f"  掃描網段 : {network_cidr}")

    # ── 埠口清單 ──
    if args.fast:
        ports_to_scan = list(PROXY_PORTS.keys()) + [p for p in VPN_PORTS if p not in (80, 443)]
        print(f"  掃描模式 : 快速（{len(ports_to_scan)} 個關鍵埠口）")
    else:
        ports_to_scan = list(ALL_SCAN_PORTS.keys())
        print(f"  掃描模式 : 完整（{len(ports_to_scan)} 個埠口）")

    if DEBUG:
        print(f"  埠口列表 : {sorted(ports_to_scan)}")
        print(f"  超時設定 : {args.timeout}s  workers: {args.workers}")

    start_time = time.time()

    # ── 主機發現 ──
    print(f"\n[1/3] 主機發現")
    hosts = arp_scan(network_cidr, timeout=args.arp_timeout)
    if not hosts:
        print("  [!] 未發現任何活躍主機")
        sys.exit(0)
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

    if DEBUG and hosts:
        _debug_first_host = hosts[0]["ip"]
        print(f"  [DEBUG] 對第一台主機 {_debug_first_host} 顯示逐埠除錯訊息")

    results = []
    for i, host in enumerate(hosts, 1):
        ip = host["ip"]
        sys.stdout.write(f"  掃描 {ip} ({i}/{len(hosts)}) ...\r")
        sys.stdout.flush()
        open_ports = scan_ports(ip, ports_to_scan,
                                max_workers=args.workers,
                                timeout=args.timeout)
        risk = assess_risk(open_ports)
        results.append({**host, "open_ports": open_ports, "risk": risk})

    print(f"  掃描完成{' '*40}")

    # ── 輸出結果 ──
    results.sort(key=lambda h: h["risk"]["score"], reverse=True)
    for i, host in enumerate(results, 1):
        print_host_report(host, i, len(results))

    scan_time = time.time() - start_time
    print_summary(results, scan_time, network_cidr, local_ip)

    if args.output:
        for h in results:
            h["open_ports"] = {str(k): v for k, v in h["open_ports"].items()}
        save_json_report(results, args.output, network_cidr, local_ip, scan_time)


if __name__ == "__main__":
    main()
