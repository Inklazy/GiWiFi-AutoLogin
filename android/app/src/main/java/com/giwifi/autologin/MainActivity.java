package com.giwifi.autologin;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    private static final String PREF_NAME = "giwifi_auth_prefs";
    private static final String KEY_ACCOUNT = "key_account";
    private static final String KEY_PASSWORD = "key_password";

    private static final String GATEWAY_PORTAL = "http://10.101.0.1";
    private static final String CHECK_URL = "http://connect.rom.miui.com/generate_204";
    private static final String USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";

    private EditText etAccount;
    private EditText etPassword;
    private Button btnLogin;
    private TextView tvStatus;
    private TextView tvLog;
    private ScrollView scrollLog;

    private SharedPreferences prefs;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private boolean isRunning = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etAccount = findViewById(R.id.etAccount);
        etPassword = findViewById(R.id.etPassword);
        btnLogin = findViewById(R.id.btnLogin);
        tvStatus = findViewById(R.id.tvStatus);
        tvLog = findViewById(R.id.tvLog);
        scrollLog = findViewById(R.id.scrollLog);

        prefs = getSharedPreferences(PREF_NAME, MODE_PRIVATE);

        btnLogin.setOnClickListener(v -> handleManualLogin());

        findViewById(R.id.btnCheck).setOnClickListener(v -> {
            if (isRunning) return;
            executor.execute(() -> {
                bindToWifiNetwork();
                checkConnectivity();
            });
        });

        findViewById(R.id.btnClear).setOnClickListener(v -> {
            prefs.edit().clear().apply();
            etAccount.setText("");
            etPassword.setText("");
            addLog("已清除本地保存的账号与密码。");
            updateStatus("已清除凭据", Color.parseColor("#E2E8F0"), Color.parseColor("#475569"));
            Toast.makeText(this, "凭据已清除", Toast.LENGTH_SHORT).show();
        });

        findViewById(R.id.btnClearLog).setOnClickListener(v -> tvLog.setText(""));

        // 读取本地持久化凭据
        String savedAcc = prefs.getString(KEY_ACCOUNT, "");
        String savedPwd = prefs.getString(KEY_PASSWORD, "");

        if (!savedAcc.isEmpty() && !savedPwd.isEmpty()) {
            etAccount.setText(savedAcc);
            etPassword.setText(savedPwd);
            String masked = savedAcc.length() > 7 ? savedAcc.substring(0, 3) + "****" + savedAcc.substring(savedAcc.length() - 4) : savedAcc;
            addLog("读取到已存账号 [" + masked + "]，自动检测网络并登录...");
            startLogin(savedAcc, savedPwd, false);
        } else {
            // 初次使用保持空白，由用户自行填入并保存
            etAccount.setText("");
            etPassword.setText("");
            addLog("初次使用，请填入个人上网账号与密码，点击【保存并一键认证】。");
            addLog("凭据将安全保存在本机，后续打开 App 会自动登录。");
        }
    }

    private void bindToWifiNetwork() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                for (Network net : cm.getAllNetworks()) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                    if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                        cm.bindProcessToNetwork(net);
                        addLog("已成功绑定网络请求至 Wi-Fi 通道。");
                        return;
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    private void updateStatus(String text, int bgColor, int textColor) {
        runOnUiThread(() -> {
            tvStatus.setText(text);
            tvStatus.setBackgroundColor(bgColor);
            tvStatus.setTextColor(textColor);
        });
    }

    private void addLog(String msg) {
        String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        String line = "[" + time + "] " + msg + "\n";
        runOnUiThread(() -> {
            tvLog.append(line);
            scrollLog.post(() -> scrollLog.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void handleManualLogin() {
        if (isRunning) return;
        String acc = etAccount.getText().toString().trim();
        String pwd = etPassword.getText().toString().trim();
        if (acc.isEmpty() || pwd.isEmpty()) {
            Toast.makeText(this, "账号或密码不能为空", Toast.LENGTH_SHORT).show();
            return;
        }

        prefs.edit().putString(KEY_ACCOUNT, acc).putString(KEY_PASSWORD, pwd).apply();
        addLog("账号密码已成功保存至本机存储。");
        startLogin(acc, pwd, true);
    }

    private void startLogin(String acc, String pwd, boolean force) {
        isRunning = true;
        runOnUiThread(() -> btnLogin.setEnabled(false));
        executor.execute(() -> {
            try {
                bindToWifiNetwork();
                doLoginProcess(acc, pwd, force);
            } finally {
                isRunning = false;
                runOnUiThread(() -> btnLogin.setEnabled(true));
            }
        });
    }

    private boolean checkConnectivity() {
        addLog("正在测试 Wi-Fi 外网连通性...");
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(CHECK_URL).openConnection();
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setInstanceFollowRedirects(false);
            int code = conn.getResponseCode();
            if (code == 204) {
                updateStatus("外网已连通", Color.parseColor("#DCFCE7"), Color.parseColor("#15803D"));
                addLog("外网已连通 (HTTP 204)，网络畅通！");
                return true;
            } else {
                updateStatus("需要认证", Color.parseColor("#FEF3C7"), Color.parseColor("#B45309"));
                addLog("Wi-Fi 受限 (HTTP " + code + ")，需要登录认证。");
                return false;
            }
        } catch (Exception e) {
            updateStatus("未联网/受限", Color.parseColor("#FEE2E2"), Color.parseColor("#B91C1C"));
            addLog("连通性测试未通: " + e.getMessage());
            return false;
        }
    }

    private void doLoginProcess(String account, String password, boolean force) {
        updateStatus("正在认证...", Color.parseColor("#E0F2FE"), Color.parseColor("#0369A1"));

        if (!force && checkConnectivity()) {
            return;
        }

        addLog("正在获取 GiWiFi 网关认证页面...");
        String loginUrl = GATEWAY_PORTAL + "/gportal/web/login";
        String html = "";

        try {
            HttpURLConnection conn204 = (HttpURLConnection) new URL(CHECK_URL).openConnection();
            conn204.setRequestProperty("User-Agent", USER_AGENT);
            conn204.setConnectTimeout(4000);
            conn204.setReadTimeout(4000);
            conn204.setInstanceFollowRedirects(false);
            int code = conn204.getResponseCode();
            if (code == 302 || code == 301) {
                String loc = conn204.getHeaderField("Location");
                if (loc != null && loc.contains("gportal")) {
                    loginUrl = loc;
                }
            }
        } catch (Exception ignored) {}

        try {
            HttpURLConnection connPage = (HttpURLConnection) new URL(loginUrl).openConnection();
            connPage.setRequestProperty("User-Agent", USER_AGENT);
            connPage.setConnectTimeout(5000);
            connPage.setReadTimeout(5000);
            InputStream in = connPage.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) != -1) {
                baos.write(buf, 0, len);
            }
            in.close();
            html = baos.toString("UTF-8");
        } catch (Exception e) {
            addLog("获取认证页面失败: " + e.getMessage() + "，请确认手机已连上校园网 Wi-Fi。");
            updateStatus("网关连接失败", Color.parseColor("#FEE2E2"), Color.parseColor("#B91C1C"));
            return;
        }

        Matcher formMatcher = Pattern.compile("<form[^>]*id=[\"']loginForm[\"'][^>]*>([\\s\\S]*?)</form>", Pattern.CASE_INSENSITIVE).matcher(html);
        if (!formMatcher.find()) {
            addLog("未在页面中找到 loginForm 表单。");
            updateStatus("解析失败", Color.parseColor("#FEE2E2"), Color.parseColor("#B91C1C"));
            return;
        }

        String formContent = formMatcher.group(1);
        Matcher inputMatcher = Pattern.compile("<input\\b([^>]*)/?>", Pattern.CASE_INSENSITIVE).matcher(formContent);

        List<String[]> inputPairs = new ArrayList<>();
        String ivStr = "";

        while (inputMatcher.find()) {
            String attrs = inputMatcher.group(1);
            Matcher nameM = Pattern.compile("name=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE).matcher(attrs);
            if (nameM.find()) {
                String name = nameM.group(1);
                Matcher valM = Pattern.compile("value=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE).matcher(attrs);
                String val = valM.find() ? valM.group(1) : "";

                if ("user_account".equals(name)) {
                    val = account;
                } else if ("user_password".equals(name)) {
                    val = password;
                } else if ("iv".equals(name)) {
                    ivStr = val;
                }
                inputPairs.add(new String[]{name, val});
            }
        }

        if (ivStr.isEmpty()) {
            addLog("表单中未找到 iv 向量，无法加密。");
            updateStatus("缺少IV向量", Color.parseColor("#FEE2E2"), Color.parseColor("#B91C1C"));
            return;
        }

        addLog("成功提取表单动态参数 (IV: " + ivStr + ")");

        StringBuilder serialized = new StringBuilder();
        try {
            for (int i = 0; i < inputPairs.size(); i++) {
                if (i > 0) serialized.append("&");
                String[] pair = inputPairs.get(i);
                serialized.append(URLEncoder.encode(pair[0], "UTF-8"))
                        .append("=")
                        .append(URLEncoder.encode(pair[1], "UTF-8"));
            }

            String encryptedData = encryptAesCbc(serialized.toString(), ivStr);
            addLog("正在向网关提交加密认证请求...");

            String postUrl = GATEWAY_PORTAL + "/gportal/Web/loginAction";
            HttpURLConnection postConn = (HttpURLConnection) new URL(postUrl).openConnection();
            postConn.setRequestMethod("POST");
            postConn.setDoOutput(true);
            postConn.setRequestProperty("User-Agent", USER_AGENT);
            postConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
            postConn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
            postConn.setRequestProperty("Referer", loginUrl);
            postConn.setRequestProperty("Origin", GATEWAY_PORTAL);
            postConn.setConnectTimeout(6000);
            postConn.setReadTimeout(6000);

            String postBody = "data=" + URLEncoder.encode(encryptedData, "UTF-8") + "&iv=" + URLEncoder.encode(ivStr, "UTF-8");
            OutputStream os = postConn.getOutputStream();
            os.write(postBody.getBytes(StandardCharsets.UTF_8));
            os.flush();
            os.close();

            InputStream is = postConn.getInputStream();
            ByteArrayOutputStream respBaos = new ByteArrayOutputStream();
            byte[] buf = new byte[2048];
            int l;
            while ((l = is.read(buf)) != -1) {
                respBaos.write(buf, 0, l);
            }
            is.close();

            String respJsonStr = respBaos.toString("UTF-8");
            JSONObject respJson = new JSONObject(respJsonStr);
            int status = respJson.optInt("status", -1);
            String info = respJson.optString("info", "");

            addLog("网关返回: [状态 " + status + "] " + info);

            if (status == 1) {
                updateStatus("认证成功", Color.parseColor("#DCFCE7"), Color.parseColor("#15803D"));
                addLog("恭喜，校园网认证成功！");
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "认证成功！", Toast.LENGTH_SHORT).show());
                checkConnectivity();
            } else {
                JSONObject dataObj = respJson.optJSONObject("data");
                if (dataObj != null && "124".equals(dataObj.optString("resultCode"))) {
                    String kickUrl = dataObj.optString("resultData");
                    if (!kickUrl.isEmpty()) {
                        addLog("检测到其他设备在线，正在自动下线旧设备...");
                        try {
                            HttpURLConnection kickConn = (HttpURLConnection) new URL(kickUrl).openConnection();
                            kickConn.setRequestMethod("POST");
                            kickConn.setRequestProperty("User-Agent", USER_AGENT);
                            kickConn.setConnectTimeout(4000);
                            kickConn.getResponseCode();
                            addLog("已发送强制登录请求，重新检测连通性...");
                            Thread.sleep(1500);
                            if (checkConnectivity()) {
                                updateStatus("认证成功", Color.parseColor("#DCFCE7"), Color.parseColor("#15803D"));
                                addLog("抢占登录成功，网络已畅通！");
                                return;
                            }
                        } catch (Exception ke) {
                            addLog("下线请求失败: " + ke.getMessage());
                        }
                    }
                }
                updateStatus("认证失败", Color.parseColor("#FEE2E2"), Color.parseColor("#B91C1C"));
            }

        } catch (Exception e) {
            addLog("认证过程异常: " + e.getMessage());
            updateStatus("认证异常", Color.parseColor("#FEE2E2"), Color.parseColor("#B91C1C"));
        }
    }

    private static String encryptAesCbc(String dataStr, String ivStr) throws Exception {
        byte[] key = "1234567887654321".getBytes(StandardCharsets.UTF_8);
        byte[] iv = ivStr.getBytes(StandardCharsets.UTF_8);
        byte[] raw = dataStr.getBytes(StandardCharsets.UTF_8);

        int padLen = (16 - (raw.length % 16)) % 16;
        byte[] padded = new byte[raw.length + padLen];
        System.arraycopy(raw, 0, padded, 0, raw.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(padded);

        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }
}
