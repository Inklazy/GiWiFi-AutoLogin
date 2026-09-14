# -*- coding: utf-8 -*-
"""
GiWiFi 校园网自动登录助手 (分享版 - 单文件免环境 EXE)
双击打开: 图形化配置账号密码、一键开启/关闭开机自启
参数 --silent: 开机无窗口静默后台运行
"""
import sys
import os
import time
import json
import base64
import re
import socket
import subprocess
import configparser
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
from html.parser import HTMLParser
import threading

# 获取程序所在根目录 (兼容直接运行与 PyInstaller 打包后的路径)
if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(APP_DIR, "config.ini")
LOG_PATH = os.path.join(APP_DIR, "giwifi_login.log")

DEFAULT_GATEWAY = "http://10.101.0.1"
DEFAULT_AC_NAME = "DZLG"
CHECK_URL = "http://connect.rom.miui.com/generate_204"
FALLBACK_CHECK_URL = "http://www.baidu.com"

# ==================== 1. AES-128-CBC ZeroPadding ====================
_S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _xtime(a):
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

def _key_expansion(key_bytes):
    w = list(key_bytes)
    for i in range(4, 44):
        temp = list(w[(i-1)*4 : i*4])
        if i % 4 == 0:
            temp = [_S_BOX[temp[1]], _S_BOX[temp[2]], _S_BOX[temp[3]], _S_BOX[temp[0]]]
            temp[0] ^= _RCON[i // 4]
        for j in range(4):
            w.append(w[(i-4)*4 + j] ^ temp[j])
    return w

def _encrypt_block(block, round_keys):
    state = list(block)
    for i in range(16):
        state[i] ^= round_keys[i]
    for r in range(1, 10):
        state = [_S_BOX[b] for b in state]
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11]
        ]
        new_state = [0] * 16
        for c in range(4):
            c4 = c * 4
            s0, s1, s2, s3 = state[c4], state[c4+1], state[c4+2], state[c4+3]
            t = s0 ^ s1 ^ s2 ^ s3
            new_state[c4]   = s0 ^ t ^ _xtime(s0 ^ s1)
            new_state[c4+1] = s1 ^ t ^ _xtime(s1 ^ s2)
            new_state[c4+2] = s2 ^ t ^ _xtime(s2 ^ s3)
            new_state[c4+3] = s3 ^ t ^ _xtime(s3 ^ s0)
        state = new_state
        rk = round_keys[r*16 : (r+1)*16]
        for i in range(16):
            state[i] ^= rk[i]
    state = [_S_BOX[b] for b in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]
    rk = round_keys[160:176]
    for i in range(16):
        state[i] ^= rk[i]
    return bytes(state)

def pure_aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> str:
    pad_len = (16 - (len(plaintext) % 16)) % 16
    padded = plaintext + b"\x00" * pad_len
    round_keys = _key_expansion(key)
    iv_curr = list(iv)
    ciphertext = bytearray()
    for i in range(0, len(padded), 16):
        block = bytes([padded[i+j] ^ iv_curr[j] for j in range(16)])
        enc_block = _encrypt_block(block, round_keys)
        ciphertext.extend(enc_block)
        iv_curr = list(enc_block)
    return base64.b64encode(ciphertext).decode("utf-8")

def encrypt_giwifi(data_str: str, iv_str: str) -> str:
    key = b"1234567887654321"
    iv = iv_str.encode("utf-8")
    raw = data_str.encode("utf-8")
    return pure_aes_cbc_encrypt(raw, key, iv)

# ==================== 2. 认证逻辑核心 ====================
class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_login_form = False
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "form" and attr_dict.get("id") == "loginForm":
            self.in_login_form = True
        elif tag == "input" and self.in_login_form:
            name = attr_dict.get("name")
            if name:
                value = attr_dict.get("value", "")
                self.inputs.append((name, value))

    def handle_endtag(self, tag):
        if tag == "form" and self.in_login_form:
            self.in_login_form = False

class GiWiFiEngine:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        self.opener.addheaders = [
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "zh-CN,zh;q=0.9"),
        ]

    def log(self, msg: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] {msg}"
        print(formatted)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except Exception:
            pass
        if self.log_callback:
            self.log_callback(msg)

    def check_online(self) -> bool:
        try:
            req = urllib.request.Request(CHECK_URL)
            with self.opener.open(req, timeout=3) as resp:
                final_url = resp.geturl()
                if resp.status == 204 and "10.101.0.1" not in final_url and "gportal" not in final_url:
                    return True
        except Exception:
            pass

        try:
            req = urllib.request.Request(FALLBACK_CHECK_URL)
            with self.opener.open(req, timeout=3) as resp:
                final_url = resp.geturl()
                body = resp.read(1024).decode("utf-8", errors="ignore")
                if resp.status == 200 and "10.101.0.1" not in final_url and ("baidu" in body or "百度" in body):
                    return True
        except Exception:
            pass

        return False

    def detect_wlan_ip(self) -> str:
        try:
            out = subprocess.check_output("ipconfig", encoding="gbk", errors="ignore")
            blocks = re.split(r"\r?\n\r?\n", out)
            for b in blocks:
                if "WLAN" in b or "无线" in b or "Wi-Fi" in b:
                    m = re.search(r"IPv4 [^\r\n:]*:\s*([0-9.]+)", b)
                    if m:
                        ip = m.group(1).strip()
                        if ip and not ip.startswith("169.254."):
                            return ip
        except Exception:
            pass
        return "10.102.115.50"

    def get_login_page(self, gateway, ac_name):
        try:
            req = urllib.request.Request(CHECK_URL)
            with self.opener.open(req, timeout=4) as resp:
                final_url = resp.geturl()
                if "gportal" in final_url and "wlanuserip=" in final_url:
                    return final_url, resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as he:
            if "gportal" in he.geturl() and "wlanuserip=" in he.geturl():
                return he.geturl(), he.read().decode("utf-8", errors="ignore")
        except Exception:
            pass

        wlan_ip = self.detect_wlan_ip()
        login_url = f"{gateway}/gportal/web/login?wlanuserip={wlan_ip}&wlanacname={ac_name}"
        req = urllib.request.Request(login_url)
        with self.opener.open(req, timeout=5) as resp:
            return resp.geturl(), resp.read().decode("utf-8", errors="ignore")

    def execute_login(self, account, password, gateway=DEFAULT_GATEWAY, ac_name=DEFAULT_AC_NAME, auto_kick=True, force=False):
        self.log("正在检测网络连通性...")
        if not force and self.check_online():
            self.log("当前网络已正常连通，无需重复认证。")
            return True, "已联网，无需认证"

        self.log("正在连接校园网网关认证页面...")
        try:
            login_url, html = self.get_login_page(gateway, ac_name)
        except Exception as e:
            msg = f"连接网关失败: {e}，请确认已连接 GiWiFi。"
            self.log(msg)
            return False, msg

        parser = LoginFormParser()
        parser.feed(html)
        if not parser.inputs:
            msg = "未在页面中找到 loginForm 表单。"
            self.log(msg)
            return False, msg

        form_pairs = []
        iv_val = ""
        for name, val in parser.inputs:
            if name == "user_account":
                val = account
            elif name == "user_password":
                val = password
            elif name == "iv":
                iv_val = val
            form_pairs.append((name, val))

        if not iv_val:
            msg = "缺少 iv 加密向量，认证终止。"
            self.log(msg)
            return False, msg

        self.log(f"成功提取动态参数 (IV={iv_val})，正在执行 AES-128-CBC 加密...")
        serialized_form = urllib.parse.urlencode(form_pairs)
        encrypted_data = encrypt_giwifi(serialized_form, iv_val)

        parsed_url = urllib.parse.urlparse(login_url)
        base_host = f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else gateway
        login_action_url = f"{base_host}/gportal/Web/loginAction"

        post_data = urllib.parse.urlencode({
            "data": encrypted_data,
            "iv": iv_val
        }).encode("utf-8")

        ajax_headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": login_url,
            "Origin": base_host
        }

        self.log("正在向网关提交加密认证请求...")
        try:
            req = urllib.request.Request(login_action_url, data=post_data, headers=ajax_headers)
            with self.opener.open(req, timeout=6) as resp:
                resp_json = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except Exception as e:
            msg = f"提交请求失败: {e}"
            self.log(msg)
            return False, msg

        status = resp_json.get("status")
        info = resp_json.get("info", "")
        data = resp_json.get("data", {})

        if status == 1:
            self.log(f"认证成功: {info}")
            time.sleep(1)
            if self.check_online():
                self.log("外网连通性验证通过，网络已恢复畅通！")
            return True, "认证成功！"
        else:
            self.log(f"网关返回提示: {info}")
            if isinstance(data, dict) and data.get("resultCode") == "124":
                kick_url = data.get("resultData")
                if kick_url and auto_kick:
                    self.log("检测到账号在其他设备登录，正在自动下线旧设备...")
                    try:
                        kick_req = urllib.request.Request(kick_url, data=b"", headers=ajax_headers)
                        with self.opener.open(kick_req, timeout=5):
                            self.log("已发送强制抢占请求，重新检测连通性...")
                            time.sleep(2)
                            if self.check_online():
                                self.log("抢占登录成功，网络已畅通！")
                                return True, "抢占登录成功！"
                    except Exception as ke:
                        self.log(f"下线请求失败: {ke}")
            return False, info

# ==================== 3. 配置文件读写 ====================
def load_config():
    cfg = configparser.ConfigParser()
    acc, pwd = "", ""
    auto_start = True
    if os.path.exists(CONFIG_PATH):
        try:
            cfg.read(CONFIG_PATH, encoding="utf-8")
            acc = cfg.get("GiWiFi", "account", fallback="")
            pwd = cfg.get("GiWiFi", "password", fallback="")
            auto_start = cfg.getboolean("GiWiFi", "autostart", fallback=True)
        except Exception:
            pass
    return acc, pwd, auto_start

def save_config(account, password, auto_start):
    cfg = configparser.ConfigParser()
    cfg["GiWiFi"] = {
        "account": account,
        "password": password,
        "autostart": "true" if auto_start else "false",
        "gateway": DEFAULT_GATEWAY,
        "ac_name": DEFAULT_AC_NAME
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        cfg.write(f)

def setup_task_scheduler(enable=True):
    task_name = "GiWiFi_AutoLogin"
    if enable:
        exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else sys.argv[0])
        # 如果是 python 脚本运行，则拼 pythonw
        if exe_path.endswith(".py"):
            cmd = f'schtasks /create /tn "{task_name}" /tr "pythonw.exe \\"{exe_path}\\" --silent" /sc onlogon /rl highest /f'
        else:
            cmd = f'schtasks /create /tn "{task_name}" /tr "\\"{exe_path}\\" --silent" /sc onlogon /rl highest /f'
        ret = os.system(cmd)
        return ret == 0
    else:
        cmd = f'schtasks /delete /tn "{task_name}" /f'
        ret = os.system(cmd)
        return ret == 0

# ==================== 4. 静默模式 (--silent) ====================
def run_silent():
    acc, pwd, _ = load_config()
    if not acc or not pwd:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 错误: 未配置账号密码，请先双击打开程序配置。\n")
        sys.exit(1)

    engine = GiWiFiEngine()
    for attempt in range(1, 6):
        engine.log(f"=== GiWiFi 开机静默认证 [{attempt}/5] ===")
        if engine.check_online():
            engine.log("外网正常，无需认证。")
            sys.exit(0)
        success, _ = engine.execute_login(acc, pwd)
        if success:
            sys.exit(0)
        time.sleep(4)
    engine.log("超过最大尝试次数，认证未成功。")
    sys.exit(1)

# ==================== 5. 图形配置界面 (Tkinter) ====================
def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title("GiWiFi 校园网自动认证配置向导")
    root.geometry("460x520")
    root.resizable(False, False)

    # 尝试设置居中
    root.update_idletasks()
    x = (root.winfo_screenwidth() - 460) // 2
    y = (root.winfo_screenheight() - 520) // 2
    root.geometry(f"+{x}+{y}")

    # 配色与样式
    bg_color = "#F8FAFC"
    card_color = "#FFFFFF"
    primary_color = "#0284C7"
    root.configure(bg=bg_color)

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TLabel", background=card_color, font=("微软雅黑", 9))
    style.configure("Header.TLabel", background=bg_color, font=("微软雅黑", 14, "bold"), foreground="#0F172A")
    style.configure("Sub.TLabel", background=bg_color, font=("微软雅黑", 9), foreground="#64748B")

    # 顶部标题
    lbl_title = ttk.Label(root, text="GiWiFi 校园网认证助手", style="Header.TLabel")
    lbl_title.pack(pady=(18, 2))
    lbl_sub = ttk.Label(root, text="开机静默登录 · 一键认证 · 离线免安装版", style="Sub.TLabel")
    lbl_sub.pack(pady=(0, 12))

    # 主卡片容器
    card = tk.Frame(root, bg=card_color, padx=20, pady=16, relief="solid", bd=1, highlightthickness=0)
    card.configure(highlightbackground="#E2E8F0", highlightcolor="#E2E8F0")
    card.pack(fill="x", padx=20)

    # 账号
    tk.Label(card, text="上网账号 / 手机号:", bg=card_color, fg="#1E293B", font=("微软雅黑", 9, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 4))
    ent_account = tk.Entry(card, font=("微软雅黑", 10), bg="#F1F5F9", relief="flat", bd=6)
    ent_account.grid(row=1, column=0, columnspan=2, sticky="we", pady=(0, 10))

    # 密码
    tk.Label(card, text="上网密码:", bg=card_color, fg="#1E293B", font=("微软雅黑", 9, "bold")).grid(row=2, column=0, sticky="w", pady=(0, 4))
    ent_password = tk.Entry(card, font=("微软雅黑", 10), show="•", bg="#F1F5F9", relief="flat", bd=6)
    ent_password.grid(row=3, column=0, columnspan=2, sticky="we", pady=(0, 10))

    # 开机自启复选框
    var_autostart = tk.BooleanVar(value=True)
    chk_auto = tk.Checkbutton(card, text="开启 Windows 开机静默自动认证 (无黑框后台运行)", variable=var_autostart,
                              bg=card_color, fg="#334155", font=("微软雅黑", 8), activebackground=card_color)
    chk_auto.grid(row=4, column=0, columnspan=2, sticky="w", pady=(2, 12))

    # 状态栏文字
    lbl_status = tk.Label(card, text="状态: 准备就绪", bg="#E2E8F0", fg="#475569", font=("微软雅黑", 8, "bold"), padx=8, pady=4)
    lbl_status.grid(row=5, column=0, columnspan=2, sticky="we", pady=(0, 10))

    card.columnconfigure(0, weight=1)

    # 操作按钮区域
    btn_frame = tk.Frame(root, bg=bg_color)
    btn_frame.pack(fill="x", padx=20, pady=8)

    btn_login = tk.Button(btn_frame, text="保存配置并立即认证", bg="#0284C7", fg="#FFFFFF", font=("微软雅黑", 10, "bold"),
                          relief="flat", activebackground="#0369A1", activeforeground="#FFFFFF", cursor="hand2")
    btn_login.pack(fill="x", ipady=6)

    sub_btn_frame = tk.Frame(root, bg=bg_color)
    sub_btn_frame.pack(fill="x", padx=20, pady=(2, 8))

    btn_test = tk.Button(sub_btn_frame, text="仅测试网络", bg="#E2E8F0", fg="#334155", font=("微软雅黑", 8),
                         relief="flat", cursor="hand2")
    btn_test.pack(side="left", padx=(0, 5))

    btn_uninstall = tk.Button(sub_btn_frame, text="卸载开机自启", bg="#E2E8F0", fg="#94A3B8", font=("微软雅黑", 8),
                              relief="flat", cursor="hand2")
    btn_uninstall.pack(side="right")

    # 日志控制台
    log_frame = tk.Frame(root, bg="#1E1E24", padx=10, pady=8)
    log_frame.pack(fill="both", expand=True, padx=20, pady=(4, 16))

    txt_log = tk.Text(log_frame, bg="#1E1E24", fg="#E2E8F0", font=("Consolas", 8), relief="flat", height=7)
    txt_log.pack(fill="both", expand=True)

    def append_log(msg):
        t = time.strftime("%H:%M:%S")
        txt_log.insert("end", f"[{t}] {msg}\n")
        txt_log.see("end")

    engine = GiWiFiEngine(log_callback=lambda m: root.after(0, append_log, m))

    # 读取初始配置
    saved_acc, saved_pwd, saved_auto = load_config()
    ent_account.insert(0, saved_acc)
    ent_password.insert(0, saved_pwd)
    var_autostart.set(saved_auto)

    if saved_acc:
        append_log("读取到已保存凭据。可直接点击【保存配置并立即认证】。")
    else:
        append_log("初次使用，请填入账号密码后点击上方按钮完成首次认证与自启配置。")

    def on_login_clicked():
        acc = ent_account.get().strip()
        pwd = ent_password.get().strip()
        if not acc or not pwd:
            messagebox.showwarning("提示", "账号或密码不能为空！")
            return

        btn_login.config(state="disabled", text="正在认证中...")
        lbl_status.config(text="状态: 正在向网关认证...", bg="#E0F2FE", fg="#0369A1")

        save_config(acc, pwd, var_autostart.get())

        def task():
            if var_autostart.get():
                ok = setup_task_scheduler(True)
                if ok:
                    append_log("已成功配置 Windows 开机静默登录任务计划！")
                else:
                    append_log("提示: 任务计划创建失败，可尝试右键以管理员运行。")

            ok, info = engine.execute_login(acc, pwd, force=True)
            def update_ui():
                btn_login.config(state="normal", text="保存配置并立即认证")
                if ok:
                    lbl_status.config(text="状态: 认证成功！", bg="#DCFCE7", fg="#15803D")
                    messagebox.showinfo("成功", "GiWiFi 校园网认证成功！\n开机自启已就绪，下次开机将自动在后台静默登录。")
                else:
                    lbl_status.config(text="状态: 认证失败", bg="#FEE2E2", fg="#B91C1C")
            root.after(0, update_ui)

        threading.Thread(target=task, daemon=True).start()

    def on_test_clicked():
        btn_test.config(state="disabled")
        def task():
            online = engine.check_online()
            def update_ui():
                btn_test.config(state="normal")
                if online:
                    lbl_status.config(text="状态: 外网已连通", bg="#DCFCE7", fg="#15803D")
                else:
                    lbl_status.config(text="状态: 外网未连通", bg="#FEF3C7", fg="#B45309")
            root.after(0, update_ui)
        threading.Thread(target=task, daemon=True).start()

    def on_uninstall_clicked():
        ok = setup_task_scheduler(False)
        if ok:
            messagebox.showinfo("提示", "已成功卸载 GiWiFi 开机任务计划！")
            append_log("已取消开机自动登录任务。")
        else:
            messagebox.showwarning("提示", "卸载失败或原本未安装任务计划。")

    btn_login.config(command=on_login_clicked)
    btn_test.config(command=on_test_clicked)
    btn_uninstall.config(command=on_uninstall_clicked)

    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["--silent", "-s", "/silent"]:
        run_silent()
    else:
        run_gui()
