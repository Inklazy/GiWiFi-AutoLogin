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
import tkinter as tk
from tkinter import ttk, messagebox
import ctypes

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


# ==================== 5. 图形配置界面 (Fluent 现代桌面风格) ====================

class FluentButton(tk.Canvas):
    """Fluent 风格按钮：支持圆角、悬浮/按下动效、禁用态与响应式重绘"""
    def __init__(self, parent, text='', command=None, bg='#0067C0', hover_bg='#1879D3', pressed_bg='#005A9E',
                 fg='#FFFFFF', disabled_bg='#E5E5E5', disabled_fg='#A0A0A0',
                 border_color=None, radius=6, font=('Microsoft YaHei UI', 9, 'bold'), height=36, **kwargs):
        super().__init__(parent, height=height, bg=parent['bg'], highlightthickness=0, **kwargs)
        self.text = text
        self.command = command
        self.normal_bg = bg
        self.hover_bg = hover_bg
        self.pressed_bg = pressed_bg
        self.fg = fg
        self.disabled_bg = disabled_bg
        self.disabled_fg = disabled_fg
        self.border_color = border_color
        self.radius = radius
        self.font = font
        self.state = 'normal'
        self.current_bg = bg

        self.bind('<Configure>', self._redraw)
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_press)
        self.bind('<ButtonRelease-1>', self._on_release)

    def _redraw(self, event=None):
        w = self.winfo_width()
        h = self.winfo_height()
        self.delete('all')
        if w <= 1 or h <= 1:
            return
        r = self.radius
        pts = [
            r, 0, w - r, 0, w, 0, w, r,
            w, h - r, w, h, w - r, h, r, h,
            0, h, 0, h - r, 0, r, 0, 0
        ]
        color = self.disabled_bg if self.state == 'disabled' else self.current_bg
        text_color = self.disabled_fg if self.state == 'disabled' else self.fg
        outline = self.border_color if self.border_color and self.state != 'disabled' else ''
        self.create_polygon(pts, fill=color, smooth=True, outline=outline, width=1)
        self.create_text(w // 2, h // 2, text=self.text, fill=text_color, font=self.font)

    def set_text(self, text):
        self.text = text
        self._redraw()

    def set_state(self, state):
        self.state = state
        self.config(cursor='hand2' if state == 'normal' else 'arrow')
        self._redraw()

    def config(self, **kwargs):
        if 'text' in kwargs:
            self.set_text(kwargs['text'])
        if 'state' in kwargs:
            self.set_state(kwargs['state'])
        if 'command' in kwargs:
            self.command = kwargs['command']

    def _on_enter(self, e):
        if self.state == 'disabled': return
        self.current_bg = self.hover_bg
        self._redraw()

    def _on_leave(self, e):
        if self.state == 'disabled': return
        self.current_bg = self.normal_bg
        self._redraw()

    def _on_press(self, e):
        if self.state == 'disabled': return
        self.current_bg = self.pressed_bg
        self._redraw()

    def _on_release(self, e):
        if self.state == 'disabled': return
        self.current_bg = self.hover_bg
        self._redraw()
        if self.command:
            self.command()


class ToggleSwitch(tk.Canvas):
    """Windows 11 风格的 Pill Toggle Switch 控件"""
    def __init__(self, parent, variable=None, command=None, bg='#FFFFFF', active_color='#0067C0', inactive_color='#8A8A8A', thumb_color='#FFFFFF', **kwargs):
        super().__init__(parent, width=42, height=22, bg=bg, highlightthickness=0, cursor='hand2', **kwargs)
        self.variable = variable
        self.command = command
        self.active_color = active_color
        self.inactive_color = inactive_color
        self.thumb_color = thumb_color

        self.bind('<Button-1>', self._toggle)
        if self.variable:
            self.variable.trace_add('write', lambda *_: self._redraw())
        self._redraw()

    def _toggle(self, event=None):
        if self.variable:
            self.variable.set(not self.variable.get())
        if self.command:
            self.command()

    def _redraw(self):
        self.delete('all')
        is_on = self.variable.get() if self.variable else True
        track_color = self.active_color if is_on else self.inactive_color
        r = 10
        w, h = 40, 20
        x0, y0 = 1, 1
        x1, y1 = x0 + w, y0 + h
        self.create_polygon([
            x0+r, y0, x1-r, y0, x1, y0, x1, y0+r,
            x1, y1-r, x1, y1, x1-r, y1, x0+r, y1,
            x0, y1, x0, y1-r, x0, y0+r, x0, y0
        ], fill=track_color, outline='', smooth=True)

        thumb_r = 7
        cy = y0 + h // 2
        cx = (x1 - r) if is_on else (x0 + r)
        self.create_oval(cx - thumb_r, cy - thumb_r, cx + thumb_r, cy + thumb_r, fill=self.thumb_color, outline='')


class RoundedBadge(tk.Canvas):
    """Fluent 胶囊状态栏徽标"""
    def __init__(self, parent, text='状态: 准备就绪', bg='#F3F3F3', fg='#5A5A5A', font=('Microsoft YaHei UI', 9, 'bold'), height=32, **kwargs):
        super().__init__(parent, height=height, bg=parent['bg'], highlightthickness=0, **kwargs)
        self.text = text
        self.badge_bg = bg
        self.fg = fg
        self.font = font
        self.bind('<Configure>', self._redraw)

    def _redraw(self, event=None):
        w = self.winfo_width()
        h = self.winfo_height()
        self.delete('all')
        if w <= 1 or h <= 1: return
        r = h // 2
        pts = [
            r, 0, w - r, 0, w, 0, w, r,
            w, h - r, w, h, w - r, h, r, h,
            0, h, 0, h - r, 0, r, 0, 0
        ]
        self.create_polygon(pts, fill=self.badge_bg, smooth=True, outline='')
        self.create_text(w // 2, h // 2, text=self.text, fill=self.fg, font=self.font)

    def update_badge(self, text, bg, fg):
        self.text = text
        self.badge_bg = bg
        self.fg = fg
        self._redraw()

    def config(self, **kwargs):
        if 'text' in kwargs:
            self.text = kwargs['text']
        if 'bg' in kwargs:
            self.badge_bg = kwargs['bg']
        if 'fg' in kwargs:
            self.fg = kwargs['fg']
        self._redraw()


class RoundedEntry(tk.Frame):
    """带有微圆角与聚焦高光边框的 Fluent 文本框"""
    def __init__(self, parent, placeholder='', show='', font=('Microsoft YaHei UI', 9), **kwargs):
        super().__init__(parent, bg=parent['bg'], **kwargs)
        self.canvas = tk.Canvas(self, height=36, bg=parent['bg'], highlightthickness=0)
        self.canvas.pack(fill='both', expand=True)

        self.entry = tk.Entry(self.canvas, font=font, show=show, bg='#FFFFFF', relief='flat', bd=0, highlightthickness=0)
        self.canvas_window = self.canvas.create_window(12, 18, window=self.entry, anchor='w')

        self.border_color = '#D1D1D1'
        self.focused_color = '#0067C0'
        self.is_focused = False

        self.canvas.bind('<Configure>', self._redraw)
        self.entry.bind('<FocusIn>', self._on_focus_in)
        self.entry.bind('<FocusOut>', self._on_focus_out)

    def _redraw(self, event=None):
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        self.canvas.delete('border')
        if w <= 1 or h <= 1: return
        r = 6
        pts = [
            r, 1, w - r, 1, w - 1, 1, w - 1, r,
            w - 1, h - r, w - 1, h - 1, w - r, h - 1, r, h - 1,
            1, h - 1, 1, h - r, 1, r, 1, 1
        ]
        color = self.focused_color if self.is_focused else self.border_color
        width = 2 if self.is_focused else 1
        self.canvas.create_polygon(pts, fill='#FFFFFF', smooth=True, outline=color, width=width, tags='border')
        self.canvas.tag_lower('border')
        self.canvas.coords(self.canvas_window, 12, h // 2)
        self.entry.config(width=max(1, (w - 24) // 9))

    def _on_focus_in(self, e):
        self.is_focused = True
        self._redraw()

    def _on_focus_out(self, e):
        self.is_focused = False
        self._redraw()

    def get(self):
        return self.entry.get()

    def insert(self, index, string):
        self.entry.insert(index, string)


def run_gui():

    root = tk.Tk()
    root.title("GiWiFi 校园网认证助手")
    root.geometry("480x600")
    root.minsize(440, 560)
    root.resizable(True, True)

    # 启用 Windows 11 DWM 圆角与浅色窗口边框增强
    try:
        root.update()
        hwnd = ctypes.windll.user32.GetAncestor(root.winfo_id(), 2)
        if hwnd:
            DWMWA_WINDOW_CORNER_PREFERENCE = 33
            pref = ctypes.c_int(2)  # DWMWCP_ROUND
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(pref), ctypes.sizeof(pref))
    except Exception:
        pass

    # 窗口居中
    root.update_idletasks()
    x = (root.winfo_screenwidth() - 480) // 2
    y = (root.winfo_screenheight() - 600) // 2
    root.geometry(f"+{x}+{y}")

    # Fluent Design System 色彩
    bg_color = "#F3F3F3"          # 浅灰色背景
    card_bg = "#FFFFFF"           # 白色卡片 Surface
    text_primary = "#1B1B1B"      # 一级文字
    text_secondary = "#5E5E5E"    # 二级次要文字
    border_subtle = "#E5E5E5"     # 细边框

    root.configure(bg=bg_color)

    # 顶部 Header 区域
    header_frame = tk.Frame(root, bg=bg_color)
    header_frame.pack(fill="x", padx=24, pady=(20, 10))

    lbl_title = tk.Label(header_frame, text="GiWiFi 校园网认证助手", font=("Microsoft YaHei UI", 16, "bold"),
                         bg=bg_color, fg=text_primary)
    lbl_title.pack(anchor="w")

    lbl_sub = tk.Label(header_frame, text="开机静默登录 · 一键认证 · 离线免安装版", font=("Microsoft YaHei UI", 9),
                       bg=bg_color, fg=text_secondary)
    lbl_sub.pack(anchor="w", pady=(2, 8))

    # 状态指示胶囊栏
    lbl_status = RoundedBadge(header_frame, text="状态: 准备就绪", bg="#E8EAED", fg="#444746")
    lbl_status.pack(fill="x")

    # 核心配置 Card (Surface Container)
    card = tk.Frame(root, bg=card_bg, padx=20, pady=16, highlightbackground=border_subtle, highlightthickness=1)
    card.pack(fill="x", padx=24, pady=(4, 12))

    lbl_card_title = tk.Label(card, text="上网凭据配置", font=("Microsoft YaHei UI", 10, "bold"), bg=card_bg, fg=text_primary)
    lbl_card_title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

    # 账号
    tk.Label(card, text="上网账号 / 手机号:", bg=card_bg, fg=text_secondary, font=("Microsoft YaHei UI", 9)).grid(row=1, column=0, sticky="w", pady=(0, 4))
    ent_account = RoundedEntry(card, font=("Microsoft YaHei UI", 10))
    ent_account.grid(row=2, column=0, columnspan=2, sticky="we", pady=(0, 10))

    # 密码
    tk.Label(card, text="上网密码:", bg=card_bg, fg=text_secondary, font=("Microsoft YaHei UI", 9)).grid(row=3, column=0, sticky="w", pady=(0, 4))
    ent_password = RoundedEntry(card, font=("Microsoft YaHei UI", 10), show="•")
    ent_password.grid(row=4, column=0, columnspan=2, sticky="we", pady=(0, 10))

    # 开机自启 Switch 开关行
    var_autostart = tk.BooleanVar(value=True)
    switch_frame = tk.Frame(card, bg=card_bg)
    switch_frame.grid(row=5, column=0, columnspan=2, sticky="we", pady=(4, 6))

    sw_auto = ToggleSwitch(switch_frame, variable=var_autostart, bg=card_bg)
    sw_auto.pack(side="left", padx=(0, 10))

    lbl_switch_text = tk.Label(switch_frame, text="Windows 开机静默自动认证 (后台无黑框)", bg=card_bg, fg=text_primary, font=("Microsoft YaHei UI", 9))
    lbl_switch_text.pack(side="left")

    card.columnconfigure(0, weight=1)

    # 按钮操作区域
    action_frame = tk.Frame(root, bg=bg_color)
    action_frame.pack(fill="x", padx=24, pady=(0, 10))

    # 主动作按钮 (Fluent Accent Primary Filled)
    btn_login = FluentButton(action_frame, text="保存配置并立即认证", height=38, radius=8,
                             bg="#0067C0", hover_bg="#1879D3", pressed_bg="#005A9E")
    btn_login.pack(fill="x", pady=(0, 8))

    # 次要操作按钮行
    sub_action_frame = tk.Frame(action_frame, bg=bg_color)
    sub_action_frame.pack(fill="x")

    btn_test = FluentButton(sub_action_frame, text="仅测试网络", height=32, radius=6,
                            bg="#FDFDFD", hover_bg="#F3F3F3", pressed_bg="#EAEAEA", fg="#242424",
                            border_color="#D1D1D1")
    sub_action_frame.columnconfigure(0, weight=1)
    sub_action_frame.columnconfigure(1, weight=1)
    btn_test.grid(row=0, column=0, sticky="we", padx=(0, 6))

    btn_uninstall = FluentButton(sub_action_frame, text="卸载开机自启", height=32, radius=6,
                                bg="#FDFDFD", hover_bg="#F3F3F3", pressed_bg="#EAEAEA", fg="#5E5E5E",
                                border_color="#D1D1D1")
    btn_uninstall.grid(row=0, column=1, sticky="we", padx=(6, 0))

    # 运行日志控制台 (Fluent Dark Terminal Surface)
    log_frame = tk.Frame(root, bg="#1E2022", padx=12, pady=10, highlightbackground="#333538", highlightthickness=1)
    log_frame.pack(fill="both", expand=True, padx=24, pady=(0, 18))

    log_header = tk.Frame(log_frame, bg="#1E2022")
    log_header.pack(fill="x", pady=(0, 6))

    lbl_log_title = tk.Label(log_header, text="运行状态与控制台日志", bg="#1E2022", fg="#8E918F", font=("Microsoft YaHei UI", 8, "bold"))
    lbl_log_title.pack(side="left")

    def clear_log():
        txt_log.delete("1.0", "end")

    btn_clear_log = tk.Label(log_header, text="清屏", bg="#1E2022", fg="#7DACF8", font=("Microsoft YaHei UI", 8), cursor="hand2")
    btn_clear_log.pack(side="right")
    btn_clear_log.bind("<Button-1>", lambda _: clear_log())

    txt_log = tk.Text(log_frame, bg="#1E2022", fg="#E3E3E3", insertbackground="#FFFFFF", font=("Consolas", 8), relief="flat", bd=0)
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
        lbl_status.config(text="状态: 正在向网关认证...", bg="#D3E3FD", fg="#041E49")

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
                    lbl_status.config(text="状态: 认证成功！", bg="#C4EED0", fg="#0A6E31")
                    messagebox.showinfo("成功", "GiWiFi 校园网认证成功！\n开机自启已就绪，下次开机将自动在后台静默登录。")
                else:
                    lbl_status.config(text="状态: 认证失败", bg="#F9DEDC", fg="#8C1D18")
            root.after(0, update_ui)

        threading.Thread(target=task, daemon=True).start()

    def on_test_clicked():
        btn_test.config(state="disabled")
        def task():
            online = engine.check_online()
            def update_ui():
                btn_test.config(state="normal")
                if online:
                    lbl_status.config(text="状态: 外网已连通", bg="#C4EED0", fg="#0A6E31")
                else:
                    lbl_status.config(text="状态: 外网未连通", bg="#FFE7A5", fg="#7C4A03")
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
