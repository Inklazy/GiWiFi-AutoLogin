# GiWiFi-AutoLogin / GiWiFi 校园网自动认证全平台助手

<p align="center">
  <img src="docs/screenshots/phone_screen.png" width="300" alt="Android App Preview" />
</p>

<p align="center">
  <b>针对国创校园网 (GiWiFi / GPortal) 的全自动化免登录解决方案</b><br>
  涵盖 Windows 开机静默后台认证（免 Python 独立 EXE）与 Android 原生极速版 App（仅 18 KB）
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Android-blue" alt="Platform" />
  <img src="https://img.shields.io/badge/Language-Python%20%7C%20Java-brightgreen" alt="Language" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License" />
  <img src="https://img.shields.io/badge/Version-v1.0.0-orange" alt="Version" />
</p>

---

## 💡 为什么需要这个项目？

很多高校采用的 **国创校园网 (GiWiFi / GPortal，默认网关 `10.101.0.1`)** 存在以下使用痛点：
1. **频繁掉线/要求重新登录**：设备锁屏、休眠或开机后必须手动在浏览器弹窗中重新输入密码；
2. **多设备挤下线冲突**：登录手机时电脑被挤下线，登录电脑时手机又断网，弹窗确认极其繁琐；
3. **安卓 5G/流量分流失效**：在开启 5G 或双通道加速的安卓手机上，连接未认证 Wi-Fi 时系统判定无网自动切走数据，导致连网关登录页都打不开；
4. **同学电脑无 Python 环境**：普通学生电脑根本没有配置 Python、pip 或相关编译工具，常规开源脚本难以开箱即用。

本项目通过对 GiWiFi 网关底层交互协议与 AES-128-CBC 加密逻辑的完整逆向，提供了一套面向普通学生、**无需任何配置环境、解压/安装即用**的双端自动认证解决方案。

---

## ✨ 核心特性

- **⚡ 毫秒级网络状态探测**：开机/启动时优先请求 MIUI `generate_204` 连通性测试。外网已通时 0.5 秒内静默退出，不产生多余请求；网络受限时自动触发认证。
- **🔐 协议级前端加密还原**：完整还原网页端 `cryptoEncode` 机制，自动提取动态 `sign`、`iv`、`sta_ip` 等关键参数，并执行 AES-128-CBC ZeroPadding 密文打包，无需依赖模拟浏览器。
- **📱 安卓底层 Wi-Fi 强制绑定**：通过 Android 原生 `ConnectivityManager.bindProcessToNetwork`，将网络请求强行锁定至 Wi-Fi 通道，彻底解决 5G 手机“因 Wi-Fi 未认证而自动走流量”导致无法访问网关的顽疾。
- **💻 Windows 绿色免安装单文件 EXE**：使用 PyInstaller 打包，内置轻量图形配置向导，一键写入 Windows 系统任务计划，实现开机后台无黑框静默运行。同学电脑**无需安装 Python**。
- **🔄 多终端冲突自动抢占**：遭遇并发设备限制（`resultCode: 124`）时，自动触发网关下线接口并抢占登录，无需手动确认。
- **🔒 隐私安全无硬编码**：源码中零个人凭据残留，账号密码均通过本地加密存储（Android `SharedPreferences` / 本地 `config.ini`），绝不上传任何云端。

---

## 📦 预编译下载 (Releases)

可以直接前往本仓库的 [Releases 页面](../../releases) 下载最新发行版：

| 平台 | 下载文件 | 说明 |
| :--- | :--- | :--- |
| **Android** | `GiWiFi认证助手_v1.0.0.apk` | **原生超轻量版**（体积仅 18 KB，冷启动 140ms），直接在手机安装运行 |
| **Windows** | `GiWiFi_AutoLogin_Windows_x64.zip` | **单文件免安装版**（包含 `GiWiFi_AutoLogin.exe`），无需安装 Python，解压即用 |

---

## 🚀 快速上手指南

### 一、 Windows 电脑端使用

#### 方案 A：使用免安装绿色 EXE（推荐给所有同学）
1. 从 Releases 下载 `GiWiFi_AutoLogin_Windows_x64.zip` 并解压到任意文件夹（如 D 盘）；
2. 双击打开 **`GiWiFi_AutoLogin.exe`**；
3. 填入你自己的上网账号与密码，保持勾选【开启 Windows 开机静默自动认证】；
4. 点击 **【保存配置并立即认证】**，提示成功后即可关闭窗口；
5. **开机自启机制**：下次电脑开机只要连上校园网 Wi-Fi，系统会在后台以 `--silent` 模式自动登录，没有任何黑色命令行弹窗。

#### 方案 B：使用纯 Python 脚本（适合开发者自建）
如果本地已安装 Python 3.8+，进入 `windows/` 目录：
1. 编辑 `giwifi_login.py` 顶部的 `GIWIFI_ACCOUNT` 与 `GIWIFI_PASSWORD`；
2. 运行脚本进行单次认证：
   ```bash
   python giwifi_login.py --force
   ```
3. 双击运行 `一键注册开机自启.bat`，即可完成系统开机任务注册。

---

### 二、 Android 手机端使用

1. 下载并安装 `GiWiFi认证助手_v1.0.0.apk`；
2. 手机连上校园网 Wi-Fi（如 `GiWiFi`）；
3. 打开 App，输入个人的上网手机号与密码，点击 **【保存并一键认证】**；
4. 认证成功后，凭据将保存在手机本地；
5. **后续自动登录**：以后只要手机连上校园网 Wi-Fi，**打开 App 就会在 1 秒内全自动检测网络并完成认证**，全程无需再点任何按钮。

---

## 🛠️ 项目工程结构

```
GiWiFi-AutoLogin/
├── android/                   # Android 原生源码工程 (Java 17 + Material 3)
│   ├── app/
│   │   ├── src/main/java/com/giwifi/autologin/MainActivity.java
│   │   └── src/main/res/layout/activity_main.xml
│   ├── build.gradle
│   └── settings.gradle
├── windows/                   # Windows 自动化与源码
│   ├── giwifi_gui.py          # Tkinter 图形界面 + 静默运行核心 (EXE打包源文件)
│   ├── giwifi_login.py        # 纯标准库单文件 Python 脚本 (零第三方库依赖)
│   ├── run_silent.vbs         # VBS 静默运行启动器
│   ├── 一键注册开机自启.bat    # Windows 任务计划注册脚本
│   └── 卸载开机自启.bat        # 卸载开机自启任务
├── release/                   # 预编译二进制安装包 (供 Release 使用)
│   ├── GiWiFi认证助手_v1.0.0.apk
│   └── GiWiFi_AutoLogin_Windows_x64.zip
├── docs/                      # 架构设计与逆向分析文档
│   ├── protocol_analysis.md   # GiWiFi 认证协议与 AES 逆向深度解析
│   └── screenshots/           # 界面预览截图
├── .gitignore
├── LICENSE                    # MIT 开源许可证
└── README.md
```

---

## 🔬 技术深入：GiWiFi 逆向与加密机理

关于网关 403 拦截、重定向机制、动态参数提取以及 AES-128-CBC ZeroPadding 的算法逆向细节，请参阅技术文档：
👉 **[GiWiFi 校园网认证协议逆向与加密算法技术分析](docs/protocol_analysis.md)**

---

## ⚠️ 免责声明

1. 本项目仅供网络技术学习、接口分析及个人校园网连接便利使用，请勿用于任何商业用途或违反校纪校规的行为；
2. 请妥善保管个人上网账号与密码，勿将包含个人凭据的文件上传至公共网络；
3. 本项目与“国创校园网”或“GiWiFi”官方无任何关联。

---

## 📄 开源许可证

本项目采用 [MIT License](LICENSE) 授权开源。
