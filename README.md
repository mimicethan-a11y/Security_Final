# MITM 自動化攻擊與防禦系統

> **CSIE NCYU — Secure Programming Final Project**  
> 第六題：Man-in-the-Middle Attack 自動化工具（Phase 4 完整版）

---

## ⚠️ 免責聲明

本工具**僅供資訊安全課程學習與實驗室環境研究使用**。請勿對任何未經授權的網路或系統執行攻擊行為。使用者須自行負責一切法律責任。

---

## 專案簡介

本專案實作了一套以 GUI 操作的中間人攻擊（Man-in-the-Middle, MITM）教學工具，涵蓋多種網路攻擊手法與對應的防禦偵測機制，並搭配一個模擬受害者的假 HTTPS 登入伺服器，用於驗證各攻擊效果。

**實驗環境：**
- 攻擊者：Kali Linux
- 受害者：Ubuntu
- 目標伺服器：Metasploitable

---

## 功能一覽

| 功能模組 | 說明 |
|---|---|
| **網段掃描** | 透過 nmap 掃描 CIDR 網段，列出 IP、MAC、主機名稱與 OS |
| **ARP Spoofing** | 偽造 ARP 封包，將流量導向攻擊者進行中間人攔截 |
| **DNS Spoofing** | 攔截 DNS 查詢，將指定網域解析至偽造 IP |
| **SSL Strip** | 將 HTTPS 連線降級為 HTTP，使明文流量可被擷取 |
| **HTTPS 攔截** | 透過 mitmproxy 對加密流量進行解密與修改 |
| **攔截規則設定** | 動態設定 cred\_swap、JS 注入、文字竄改、重導向等規則 |
| **防禦偵測** | 偵測 ARP 快取異常，警示網路中的潛在 MITM 攻擊 |
| **Ubuntu 防禦模組** | 在受害端啟用靜態 ARP 綁定等防禦措施 |

---

## 檔案結構

```
Security_Final/
├── mitm_tool.py     # 主程式：tkinter GUI + 所有攻擊與防禦邏輯
├── intercept.py     # mitmproxy addon：HTTPS 流量攔截與修改規則
└── server.py        # 假 HTTPS 登入伺服器（用於示範攻擊效果）
```

---

## 環境需求

- Python 3.8+
- Kali Linux（建議）
- **需以 root 身分執行**

### 安裝相依套件

```bash
pip install scapy python-nmap netfilterqueue mitmproxy
apt install python3-tk wireshark-qt sslstrip dsniff
```

---

## 使用方式

### 1. 啟動主工具（需 root）

```bash
sudo python3 mitm_tool.py
```

### 2. 啟動假 HTTPS 伺服器（用於測試）

先產生自簽憑證：

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

啟動伺服器：

```bash
sudo python3 server.py
```

伺服器預設監聽 `0.0.0.0:443`，提供：
- `GET /` — 假登入頁面
- `POST /login` — 登入處理（印出帳密）
- `GET /admin` — 重導向攻擊的目標頁

### 3. 設定 HTTPS 攔截規則

intercept.py 透過環境變數控制攻擊規則，通常由 mitm_tool.py GUI 自動帶入，也可手動設定：

```bash
export MITM_RULES="cred_swap,inject_js,replace_text,redirect"
export MITM_FAKE_USER="hacker"
export MITM_FAKE_PASS="owned"
export MITM_REPLACE_FROM="登入成功"
export MITM_REPLACE_TO="登入失敗（已被攻擊者竄改）"
```

---

## 攔截規則說明

| 規則名稱 | 效果 |
|---|---|
| `cred_swap` | 竄改 POST 表單中的帳號與密碼 |
| `inject_js` | 在 HTML 回應中注入 JavaScript |
| `replace_text` | 替換 HTML 回應中的指定文字 |
| `redirect` | 將特定請求路徑強制重導向 |

---

## 攻擊流程範例

```
受害者 (Ubuntu)
     │
     │  ARP Spoofing → 流量導向攻擊者
     ▼
攻擊者 (Kali Linux)
  ├─ SSL Strip       → HTTP 明文側錄
  ├─ DNS Spoofing    → 偽造 DNS 回應
  └─ HTTPS 攔截      → 解密 / 竄改 / 注入
     │
     ▼
目標伺服器 (Metasploitable / server.py)
```

---

## 注意事項

- ARP Spoofing 停止時，工具會自動發送修復封包，恢復受害者與閘道的正確 ARP 對應。
- 防禦偵測模組可在受害端執行，偵測 ARP 快取中是否有異常。
- HTTPS 攔截需搭配 mitmproxy CA 憑證安裝至受害者信任儲存區才能完整運作。

---

## 課程資訊

- 課程：Secure Programming（資訊安全程式設計）
- 系所：國立中正大學 資訊工程學系（CSIE NCYU）
