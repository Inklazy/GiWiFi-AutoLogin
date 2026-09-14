# -*- coding: utf-8 -*-
"""
GiWiFi 校园网开机静默自动认证脚本 (支持无第三方库依赖运行)
"""
import sys
import os
import time
import json
import base64
import re
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
from html.parser import HTMLParser

# ==================== 1. 用户配置区域 ====================
GIWIFI_ACCOUNT = ""       # 你的上网账号 (通常为手机号或学号)
GIWIFI_PASSWORD = ""        # 你的上网密码
PORTAL_GATEWAY = "http://10.101.0.1" # 默认网关Portal地址
DEFAULT_AC_NAME = "DZLG"             # 默认 AC 名称 (抓包或HTML中的 wlanacname)
CHECK_URL = "http://connect.rom.miui.com/generate_204"  # 优先检测地址 (返回 204 说明已通网)
FALLBACK_CHECK_URL = "http://www.baidu.com"             # 备用检测地址
AUTO_KICK_CONCURRENT = True          # 遇到账号在其他设备登录时，是否自动下线旧设备并登录
MAX_RETRIES = 5                      # 开机网络获取IP可能有延迟，最大重试次数
RETRY_INTERVAL = 5                   # 重试等待间隔 (秒)
LOG_FILE = "giwifi_login.log"        # 日志保存文件 (方便静默运行时排错)
FORCE_LOGIN = False                  # 是否强制认证 (忽略网络连通性检查)
# ========================================================

# 支持命令行参数 --force 或 -f 强制登录测试
if len(sys.argv) > 1 and sys.argv[1].lower() in ["-f", "--force", "force"]:
    FORCE_LOGIN = True

def log(msg: str):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] {msg}"
    print(formatted)
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILE)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    except Exception:
        pass

# ==================== 2. AES-128-CBC 加密实现 ====================
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
    pad_len = (16 - (len(raw) % 16)) % 16
    padded = raw + b"\x00" * pad_len

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return base64.b64encode(ct).decode("utf-8")
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(padded)
        return base64.b64encode(ct).decode("utf-8")
    except ImportError:
        pass

    return pure_aes_cbc_encrypt(raw, key, iv)

# ==================== 3. HTML 解析与网络驱动 ====================
class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_login_form = False
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "form":
            if attr_dict.get("id") == "loginForm":
                self.in_login_form = True
        elif tag == "input" and self.in_login_form:
            name = attr_dict.get("name")
            if name:
                value = attr_dict.get("value", "")
                self.inputs.append((name, value))

    def handle_endtag(self, tag):
        if tag == "form" and self.in_login_form:
            self.in_login_form = False

class GiWiFiClient:
    def __init__(self):
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )
        # 全局添加 User-Agent，避免 urllib 重定向时丢弃 Header 导致网关 403 Forbidden
        self.opener.addheaders = [
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "zh-CN,zh;q=0.9"),
        ]

    def check_online(self) -> bool:
        """检测当前是否已正常连通外网"""
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
                body_sample = resp.read(1024).decode("utf-8", errors="ignore")
                if resp.status == 200 and "10.101.0.1" not in final_url and ("baidu" in body_sample or "百度" in body_sample):
                    return True
        except Exception:
            pass

        return False

    def detect_wlan_ip(self) -> str:
        """获取本地 WLAN (无线网卡) 分配到的内网 IP (例如 10.102.x.x)"""
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

    def get_login_page(self):
        """访问并获取认证页面 HTML 及其跳转 URL"""
        # 1. 尝试从检测地址触发网关重定向
        try:
            req = urllib.request.Request(CHECK_URL)
            with self.opener.open(req, timeout=4) as resp:
                final_url = resp.geturl()
                if "gportal" in final_url and "wlanuserip=" in final_url:
                    html = resp.read().decode("utf-8", errors="ignore")
                    return final_url, html
        except urllib.error.HTTPError as he:
            if "gportal" in he.geturl() and "wlanuserip=" in he.geturl():
                html = he.read().decode("utf-8", errors="ignore")
                return he.geturl(), html
        except Exception:
            pass

        # 2. 自动检测 WLAN IP 并构造标准入口
        wlan_ip = self.detect_wlan_ip()
        login_url = f"{PORTAL_GATEWAY}/gportal/web/login?wlanuserip={wlan_ip}&wlanacname={DEFAULT_AC_NAME}"
        req = urllib.request.Request(login_url)
        with self.opener.open(req, timeout=5) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            return resp.geturl(), html

    def login(self) -> bool:
        log("开始检测网络连接状态...")
        if not FORCE_LOGIN and self.check_online():
            log("当前网络已正常连通，无需认证。")
            return True

        if FORCE_LOGIN:
            log("已开启强制认证模式 (跳过连通性检查)...")

        log("正在获取 GiWiFi 认证页面参数...")
        try:
            login_url, html = self.get_login_page()
        except Exception as e:
            log(f"获取认证页面失败: {e}，请确认是否已连接校园网 Wi-Fi。")
            return False

        # 解析表单字段
        parser = LoginFormParser()
        parser.feed(html)
        if not parser.inputs:
            log("未在页面中找到 loginForm 表单，请检查当前网络或网关地址。")
            return False

        form_dict = {}
        form_pairs = []
        iv_val = ""
        for name, val in parser.inputs:
            if name == "user_account":
                val = GIWIFI_ACCOUNT
            elif name == "user_password":
                val = GIWIFI_PASSWORD
            elif name == "iv":
                iv_val = val
            form_dict[name] = val
            form_pairs.append((name, val))

        if not iv_val:
            log("表单中缺少 iv 加密向量，认证终止。")
            return False

        log(f"成功提取动态参数 (sta_ip={form_dict.get('sta_ip')}, nas_name={form_dict.get('nas_name')}, iv={iv_val})")

        # 1. 表单序列化
        serialized_form = urllib.parse.urlencode(form_pairs)

        # 2. AES-128-CBC 加密
        encrypted_data = encrypt_giwifi(serialized_form, iv_val)

        # 3. 构造 POST 提交数据
        parsed_url = urllib.parse.urlparse(login_url)
        base_host = f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else PORTAL_GATEWAY
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

        log("正在提交加密认证请求...")
        try:
            req = urllib.request.Request(login_action_url, data=post_data, headers=ajax_headers)
            with self.opener.open(req, timeout=6) as resp:
                resp_text = resp.read().decode("utf-8", errors="ignore")
                resp_json = json.loads(resp_text)
        except Exception as e:
            log(f"认证请求发送失败: {e}")
            return False

        status = resp_json.get("status")
        info = resp_json.get("info", "")
        data = resp_json.get("data", {})

        if status == 1:
            log(f"认证成功: {info}")
            time.sleep(1)
            if self.check_online():
                log("外网连通性验证通过，网络正常！")
            else:
                log("网关提示登录成功，稍后生效。")
            return True
        else:
            log(f"认证返回失败: {info}")
            # 处理设备冲突下线情况 (resultCode == 124)
            if isinstance(data, dict) and data.get("resultCode") == "124":
                kick_url = data.get("resultData")
                if kick_url and AUTO_KICK_CONCURRENT:
                    log("检测到其他设备在线，正在自动下线旧设备...")
                    try:
                        kick_req = urllib.request.Request(kick_url, data=b"", headers=ajax_headers)
                        with self.opener.open(kick_req, timeout=5):
                            log("已发送强制登录请求，重新检测连通性...")
                            time.sleep(2)
                            if self.check_online():
                                log("抢占登录成功，外网已恢复！")
                                return True
                    except Exception as ke:
                        log(f"下线请求失败: {ke}")
            return False

def main():
    client = GiWiFiClient()
    for attempt in range(1, MAX_RETRIES + 1):
        log(f"=== GiWiFi 自动认证尝试 [{attempt}/{MAX_RETRIES}] ===")
        if not FORCE_LOGIN and client.check_online():
            log("网络已通，无需重复认证。")
            return 0
        success = client.login()
        if success:
            return 0
        if attempt < MAX_RETRIES:
            log(f"等待 {RETRY_INTERVAL} 秒后重试...")
            time.sleep(RETRY_INTERVAL)
    log("超过最大重试次数，认证未成功。")
    return 1

if __name__ == "__main__":
    sys.exit(main())

