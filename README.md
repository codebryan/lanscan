# lanscan — 區域網路住宅代理節點偵測工具

針對 ISP 通報「疑似住宅代理（Residential Proxy）節點」問題，掃描區域網路上所有活躍主機，識別設備資訊、開放埠口，並進行代理/VPN 風險評估。

## 功能

| 功能 | 說明 |
|------|------|
| 主機發現 | ARP 掃描（需 root）或 Ping 掃描，列出所有活躍 IP |
| 設備識別 | MAC 位址、廠商名稱（OUI 查詢）、主機名稱（反向 DNS）|
| 埠口掃描 | 並行 TCP connect 掃描，偵測 30+ 個關鍵埠口 |
| 風險評估 | 依代理/VPN 埠口組合評分（LOW → CRITICAL）|
| 報告輸出 | 終端彩色報告 + JSON 報告匯出 |

## 安裝

```bash
pip install -r requirements.txt
```

## 使用方式

```bash
# 完整掃描（自動偵測網段，建議 sudo 以啟用 ARP 掃描取得 MAC）
sudo python3 lanscan.py

# 指定網段
sudo python3 lanscan.py -n 192.168.1.0/24

# 快速模式（只掃代理/VPN 關鍵埠，速度較快）
sudo python3 lanscan.py --fast

# 輸出 JSON 報告
sudo python3 lanscan.py -o report.json

# 調整超時與並行數（大型網段可增加 workers）
sudo python3 lanscan.py -t 0.5 -w 100
```

## 風險等級說明

| 等級 | 條件 |
|------|------|
| **CRITICAL** | 分數 ≥ 60，偵測到代理埠（如 1080/3128）或多重代理組合 |
| **HIGH** | 分數 ≥ 35，偵測到 VPN 或單一高風險代理埠 |
| **MEDIUM** | 分數 ≥ 15，偵測到可疑服務埠 |
| **LOW** | 分數 < 15，無明顯代理指標 |

## 重點偵測埠口

**代理類（Proxy）**
- `1080` — SOCKS4/5（最常見住宅代理）
- `3128` — Squid HTTP Proxy
- `8080` / `8888` — HTTP 代理替代埠
- `9050` / `9051` — Tor 網路

**VPN 類**
- `1194` — OpenVPN
- `51820` — WireGuard
- `1723` — PPTP

**IoT/高風險**
- `2323` — Telnet 替代埠（Mirai 殭屍網路）
- `5555` — Android Debug Bridge
- `6379` — Redis（無認證常被利用）

## 注意事項

- ARP 掃描需要 root / sudo 權限；無 root 時自動降級為 Ping 掃描（無法取得 MAC）
- 掃描結果僅供參考，開放埠口不代表一定遭入侵，需結合設備實際用途判斷
- 偵測到 CRITICAL 主機時，建議進入該設備確認是否有不明代理程式或 VPN 服務
