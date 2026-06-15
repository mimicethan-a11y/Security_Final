# MITM 自動化攻擊與防禦系統

一套以 GUI 操作的中間人攻擊（Man-in-the-Middle）教學工具，涵蓋 ARP Spoofing、DNS Spoofing、SSL Strip、HTTPS 攔截與封包竄改，並整合防禦偵測與靜態 ARP 綁定防禦功能。

---

## 實驗環境

| 主機 | 角色 | IP | 介面 |
|---|---|---|---|
| Kali Linux | 攻擊者 / 中間人 C | `10.0.0.15` | `eth1` |
| Ubuntu | 受害者 A | `10.0.0.5` | `enp0s8` |
| Ubuntu Server | 目標 Server B | `10.0.0.6` | `enp0s8` |

網路拓樸（Internal Network：`mitm-lab`）：

```
VirtualBox Host
       │
  Internal Network
  ┌────┼────┐
  A         C         B
  受害者    攻擊者    伺服器
```

---

## 檔案結構

```
Security_Final/
├── mitm_tool.py     # 主程式：tkinter GUI + 所有攻擊與防禦邏輯
├── intercept.py     # mitmproxy addon：HTTPS 流量攔截與封包竄改規則
└── server.py        # 假 HTTPS 登入伺服器（供攻擊示範用）
```

---

## 安裝相依套件

```shell
sudo apt install python3-nmap python3-scapy python3-tk
pip install mitmproxy netfilterqueue
sudo apt install sslstrip dsniff
```

---

## 啟動方式

```shell
sudo python3 mitm_tool.py
```

> 需要 root 權限執行

---

## 功能說明

### 前置：Internal Network 設定

**C（Kali）**
```shell
sudo nmcli connection add type ethernet ifname eth1 con-name mitm-lab ip4 10.0.0.15/24
sudo nmcli connection up mitm-lab
```

**A（Ubuntu 受害者）**
```shell
sudo nmcli connection add type ethernet ifname enp0s8 con-name mitm-lab ip4 10.0.0.5/24
sudo nmcli connection up mitm-lab
```

**B（Ubuntu Server）**
```shell
sudo nmcli connection add type ethernet ifname enp0s8 con-name mitm-lab ip4 10.0.0.6/24
sudo nmcli connection up mitm-lab
```

---

### 1. ARP Spoofing

**概念：**

正常流量：
```
Ubuntu → Gateway（10.0.2.1）→ Metasploitable（10.0.2.4）
```

ARP Spoofing 後：
```
Ubuntu → 誤以為 10.0.2.1 是 Kali → Kali → Gateway → Metasploitable
```

**步驟：**
1. 可先點「掃描區網」讓 GUI 自動帶出受害者 IP，或直接手動輸入
2. 填入介面、受害者 IP、目標 Server IP
3. 點「啟動 ARP 攻擊」
4. 停止時點「停止並修復」，工具會自動發送修復封包還原 ARP 對應

> 可用 `ip route | grep default` 確認 Gateway IP

---

### 2. DNS Spoofing

> ⚠️ 需先啟用 ARP Spoofing

在 DNS Spoofing 分頁中：
1. 輸入要攔截的網域與偽造 IP
2. 點「+ 加入」加入規則
3. 點「啟動 DNS Spoofing」

受害者查詢指定網域時，DNS 回應將被偽造為攻擊者設定的 IP。

---

### 3. SSL Strip

> ⚠️ 需先啟用 ARP Spoofing

**攻擊步驟：**
1. 點「啟動 SSL Strip」→ 自動設定 iptables 將 HTTP/HTTPS 流量導向本機 8080
2. 受害者連線到 HTTPS 網站時被降級為 HTTP 明文
3. Wireshark 過濾器輸入 `http`，可看到明文帳密
4. 停止時自動清除 iptables 規則

**困難點：**

現代瀏覽器普遍有 HSTS 保護，會強制使用 HTTPS 並拒絕被降級。在 Firefox / Chrome 對 Google 等主流網站實測完全無法降級，這也是為何後續改採 mitmproxy 透明代理方式進行 HTTPS 攔截。

**SSL Strip vs HTTPS 攔截比較：**

| 項目 | SSL Strip | HTTPS 攔截（mitmproxy）|
|---|---|---|
| 原理 | 把 HTTPS 降級成 HTTP | 真正解密 TLS |
| 受害者需要做什麼 | 不用 | 必須安裝攻擊者 CA |
| 對現代網站有效 | 大多無效（HSTS 防護）| 有效（前提 CA 被信任）|
| 對 curl / API 有效 | 完全無效 | 有效 |
| 攻擊難度 | 低，但成功率低 | 高，但成功率高 |

---

### 4. HTTPS 攔截（mitmproxy）

> ⚠️ 需先啟用 ARP Spoofing

**核心概念：**

整個 HTTPS 中間人攻擊的成敗，完全取決於受害者 A 是否信任攻擊者 C 的根 CA。

mitmproxy 並不是「破解」TLS，而是**分別當 A 的合法 server 和 B 的合法 client**，將原本一條 TLS 連線拆成兩條：

```
A ⇄ （TLS #1，key #1）Kali ⇄ （TLS #2，key #2）B
     ↑                              ↑
  用假憑證簽 key #1           用正常 TLS 協商 key #2
```

Kali 兩端都是當事人，因此兩端的明文都看得到。

#### 前置：B 架設 HTTPS Server

產生自簽憑證（CN 必須與 B 的 IP 一致）：

```shell
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=10.0.0.6"
```

啟動 server.py：

```shell
sudo python3 server.py
```

#### 前置：安裝 mitmproxy CA 到受害者

在 A 上允許 SSH 密碼登入（編輯 `/etc/ssh/sshd_config`，設定 `PasswordAuthentication yes`，然後重啟 SSH）：

```shell
sudo systemctl restart ssh
```

在 C 上傳送 CA 憑證到 A：

```shell
sudo scp /root/.mitmproxy/mitmproxy-ca-cert.pem user@10.0.0.5:/tmp/
```

在 A 上信任 mitmproxy CA：

```shell
sudo cp /tmp/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

#### 攻擊步驟

1. 在 GUI 點「顯示 CA 路徑」確認 CA 已產生，並依上述步驟分發到受害者
2. 重新啟動 HTTPS 攔截
3. 受害者對 `https://10.0.0.6/` 發出請求後，GUI 即時顯示解密後的明文帳密

---

### 5. 封包竄改規則（搭配 intercept.py）

> ⚠️ 需先啟用 ARP Spoofing，再選擇攔截規則，最後啟動 HTTPS 攔截

實作影片：https://youtu.be/iNp8mKl6IXI

| 規則 | 效果 |
|---|---|
| **帳密替換**（`cred_swap`）| 竄改 POST 表單中的 username / password |
| **JS 注入**（`inject_js`）| 在 HTML 回應中注入任意 JavaScript |
| **文字替換**（`replace_text`）| 替換 HTML 回應中的指定文字 |
| **強制重導**（`redirect`）| 將特定請求路徑改寫為另一路徑 |

規則透過環境變數控制，由 GUI 自動帶入，也可手動設定：

```shell
export MITM_RULES="cred_swap,inject_js,replace_text,redirect"
export MITM_FAKE_USER="hacker"
export MITM_FAKE_PASS="owned"
export MITM_REPLACE_FROM="登入成功"
export MITM_REPLACE_TO="登入失敗（已被攻擊者竄改）"
```

---

## 防禦

### ARP Spoofing 偵測（Scapy）

在防禦偵測分頁輸入：
- 監聽介面：`enp0s8`
- 監控 IP：`10.0.0.6`
- 正確 MAC：`08:00:27:79:b1:34`

點「啟動防禦偵測」後，系統使用 Scapy 監聽 ARP Reply，偵測到異常時輸出：

```
WARNING: ARP Spoofing Detected!
Watched IP   : 10.0.0.6
Expected MAC : 08:00:27:79:b1:34
Current MAC  : 08:00:27:17:ee:42
Reason       : The IP is using an unexpected MAC address.
```

**偵測邏輯：**
- **基本偵測：** 同一 IP 在 ARP Reply 中出現多個不同 MAC，判定可能發生 ARP Spoofing
- **強化偵測：** 預先指定重要主機的合法 MAC，一旦偵測到對應到其他 MAC 立即警示

---

### 靜態 ARP 綁定（Ubuntu Victim 端）

實作影片：https://youtu.be/weEn3MYX1t8

在 Ubuntu Victim 分頁輸入保護的 Server IP 與正確 MAC，點「啟動靜態 ARP 防禦」，系統執行：

```shell
sudo arp -s 10.0.0.6 08:00:27:79:b1:34
```

ARP Table 會出現 `PERM`（permanent）標記：

```
? (10.0.0.6) at 08:00:27:79:b1:34 [ether] PERM on enp0s8
```

即使 Kali 持續送出偽造 ARP Reply，受害者的 ARP Table 仍維持正確 MAC，攻擊失效。

點「解除靜態 ARP 防禦」後，`PERM` 紀錄消失，ARP Table 再次可被污染。

---

### 其他防禦對策

| 對策 | 說明 |
|---|---|
| **靜態 ARP 綁定** | 簡單直接，但大規模網路維護不易 |
| **Dynamic ARP Inspection（DAI）** | 在交換器層級阻擋偽造 ARP Reply |
| **ArpWatch / XArp** | 持續監控 IP-MAC 對應異常，變動時通知管理者 |
| **HTTPS + HSTS** | 防止 SSL Strip 降級，但若受害者誤信攻擊者 CA，mitmproxy 攔截仍可能成功 |
| **VPN** | 加密整段流量，即使 ARP Spoofing 成功也難以讀取明文 |
| **憑證信任管理** | 定期檢查系統信任憑證清單，避免安裝不明來源 CA；搭配 Certificate Pinning 偵測憑證替換 |
