# GiWiFi 校园网认证协议逆向与加密算法技术分析

本项目对国创校园网（GiWiFi / GPortal，常见网关 `10.101.0.1`）在未认证状态下的 Portal 登录页面、JavaScript 脚本及交互接口进行了深度逆向还原。

---

## 1. 认证流程生命周期

1. **未认证拦截与重定向**：
   - 设备连接校园网 Wi-Fi（SSID 通常为 `GiWiFi` 或学校特定名称）后，网关会拦截所有 HTTP 80 端口请求。
   - 访问检测地址（如 `http://connect.rom.miui.com/generate_204` 或任意未加密网页）时，网关通过 `302 Found` 重定向至：
     ```
     http://10.101.0.1/gportal/web/login?wlanuserip=<STA_IP>&wlanacname=<AC_NAME>
     ```
   - 若直接访问不带参数的 `http://10.101.0.1/gportal/web/login`，网关 Nginx 会直接返回 `403 Forbidden`。

2. **动态下发表单与会话签名**：
   - 网关返回的 HTML 页面中包含 `<form id="loginForm">`，内部嵌入了每次访问动态生成的关键字段：
     - `sign`：网关防伪数字签名（一段较长的 Base64 字符串）；
     - `iv`：本次登录专用的 AES 加密向量（16 位 Hex 字符串，如 `074acd1000a406a1`）；
     - `sta_ip` / `request_ip`：当前无线网卡分配到的内网 IP；
     - `nas_name`：认证控制器 AC 名称（如 `DZLG`）。

3. **全表单序列化与 AES-128-CBC 加密**：
   - 前端脚本获取用户填写的 `user_account` 和 `user_password`；
   - 对整个表单进行标准 URL 编码序列化（等同于 jQuery `$(form).serialize()`）；
   - 将序列化得到的字符串送入 `cryptoEncode(data, iv)` 进行 AES 加密。

4. **POST 提交认证**：
   - 请求地址：`POST http://10.101.0.1/gportal/Web/loginAction`
   - 请求体：`data=<URL编码的AES密文>&iv=<动态IV>`
   - 请求头要求携带 `X-Requested-With: XMLHttpRequest` 以及合法浏览器的 `User-Agent`（Python 默认 User-Agent 会被网关拦截）。

5. **响应解析与多设备并发抢占**：
   - 响应格式为 JSON：
     ```json
     {
       "status": 1,
       "info": "认证中，请勿关闭当前页面！",
       "data": "logout?aid=...&sign=..."
     }
     ```
   - 若 `status == 1`：认证成功，网关放行外网流量。
   - 若 `status == 0` 且 `data.resultCode == "124"`：表示账号已在其他终端登录，网关会在 `data.resultData` 中下发踢下线接口 URL。发送 POST 请求至该接口即可强制将旧设备下线并完成当前设备的抢占登录。

---

## 2. 前端加密算法还原

### 算法参数
- **算法**：AES-128-CBC
- **密钥 (Key)**：`1234567887654321`（16 字节 UTF-8 编码固定密钥）
- **向量 (IV)**：动态下发（16 字节 UTF-8 编码）
- **填充 (Padding)**：ZeroPadding（零填充，以 `\x00` 补齐至 16 字节的整数倍；若数据长度刚好为 16 字节整数倍，则不追加补齐块）
- **输出格式**：Base64 字符串

### 原网页 JS 源码
```javascript
function cryptoEncode(data, iv) {
    var key = CryptoJS.enc.Utf8.parse("1234567887654321");
    var ivv = CryptoJS.enc.Utf8.parse(iv);
    var encrypted = CryptoJS.AES.encrypt(data, key, { 
        iv: ivv, 
        mode: CryptoJS.mode.CBC, 
        padding: CryptoJS.pad.ZeroPadding 
    });
    return {'data': encrypted.toString(), 'iv': iv};
}
```

---

## 3. 移动端与双网卡环境下的核心技术突破

1. **Android 5G / 双通道加速流量漂移问题**：
   - 很多同学在宿舍同时开启了 5G 移动数据与 Wi-Fi。当连接到未认证的 Wi-Fi 时，Android 系统检测到“无互联网访问”，会自动将流量切至蜂窝网络，导致无法与内网网关 `10.101.0.1` 通信。
   - **解决方案**：在 Android 原生层通过 `ConnectivityManager.bindProcessToNetwork()` 将 App 的底层 Socket 严格锁定至 Wi-Fi 通道，彻底规避双网卡漂移问题。

2. **Windows 双网卡（有线 + 无线）冲突**：
   - 当电脑同时插入有线网（或开启代理）且连接 Wi-Fi 时，默认路由会导致请求通过有线网卡发送，GiWiFi 网关识别到源 IP 非 Wi-Fi 网段会直接抛出 `CHALLENGE_ERR_DENY`。
   - **解决方案**：自动枚举系统无线适配器 WLAN 的真实 10.x.x.x IP 并注入参数，保证请求严格匹配无线网卡身份。
