package com.cdn.vpn;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.widget.NestedScrollView;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.progressindicator.LinearProgressIndicator;
import com.google.android.material.textfield.MaterialAutoCompleteTextView;
import com.google.android.material.textfield.TextInputEditText;

public class MainActivity extends AppCompatActivity implements TunState.Listener {

    private static final int REQ_VPN = 1001;
    private static final int REQ_NOTIF = 1002;

    private TextInputEditText etIp, etHost, etPassword, etPort, etConns, etDns, etMtu;
    private TextInputEditText etLink;
    private MaterialSwitch swUdp, swBlockAaaa, swDebug;
    private MaterialAutoCompleteTextView ddMethod, ddTransport;
    private MaterialSwitch swFastopen;
    private MaterialButton btnToggle, btnClear;
    private TextView tvStatus, tvStatusDetail, tvConn, tvLog, chevAdvanced, chevManual;
    private TextView tvProfile;
    private MaterialButton btnImport, btnPaste, btnWipe;
    private TextView tvDownTotal, tvDownRate, tvUpTotal, tvUpRate, tvConns, tvUdp, tvRtt;
    private LinearProgressIndicator progress;
    private NestedScrollView logScroll;
    private View boxAdvanced, hdrAdvanced, boxManual, hdrManual;
    private View tabTunnel, tabTraffic, tabServer;
    // server tab
    private TextInputEditText etSshHost, etSshPort, etSshUser, etSshPass, etServerAddr, etServerPass, etRestartMin;
    private MaterialAutoCompleteTextView ddServerMethod;
    private MaterialButton btnDeploy, btnCheck, btnUninstall, btnAdmin, btnGenKey;
    private LinearProgressIndicator deployProgress;
    private TextView tvDeploy;
    private volatile boolean deploying = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etIp = f(R.id.et_ip); etHost = f(R.id.et_host); etPassword = f(R.id.et_password);
        etPort = f(R.id.et_port); etConns = f(R.id.et_conns);
        etDns = f(R.id.et_dns); etMtu = f(R.id.et_mtu);
        etLink = f(R.id.et_link);
        swUdp = findViewById(R.id.sw_udp);
        swBlockAaaa = findViewById(R.id.sw_block_aaaa);
        swDebug = findViewById(R.id.sw_debug);
        ddMethod = findViewById(R.id.dd_method);
        ddMethod.setSimpleItems(new String[]{"post", "get"});
        ddTransport = findViewById(R.id.dd_transport);
        ddTransport.setSimpleItems(new String[]{"chunked", "stream"});
        swFastopen = findViewById(R.id.sw_fastopen);
        btnToggle = findViewById(R.id.btn_toggle);
        btnClear = findViewById(R.id.btn_clear);
        tvStatus = findViewById(R.id.tv_status);
        tvStatusDetail = findViewById(R.id.tv_status_detail);
        tvConn = findViewById(R.id.tv_conn);
        tvLog = findViewById(R.id.tv_log);
        progress = findViewById(R.id.progress);
        logScroll = findViewById(R.id.tab_traffic); // журнал теперь внизу вкладки «Трафик»
        chevAdvanced = findViewById(R.id.chev_advanced);
        boxAdvanced = findViewById(R.id.box_advanced);
        hdrAdvanced = findViewById(R.id.hdr_advanced);
        chevManual = findViewById(R.id.chev_manual);
        boxManual = findViewById(R.id.box_manual);
        hdrManual = findViewById(R.id.hdr_manual);
        tvProfile = findViewById(R.id.tv_profile);
        btnImport = findViewById(R.id.btn_import);
        btnPaste = findViewById(R.id.btn_paste);
        btnWipe = findViewById(R.id.btn_wipe);

        tvDownTotal = findViewById(R.id.tv_down_total);
        tvDownRate = findViewById(R.id.tv_down_rate);
        tvUpTotal = findViewById(R.id.tv_up_total);
        tvUpRate = findViewById(R.id.tv_up_rate);
        tvConns = findViewById(R.id.tv_conns);
        tvUdp = findViewById(R.id.tv_udp);
        tvRtt = findViewById(R.id.tv_rtt);

        tabTunnel = findViewById(R.id.tab_tunnel);
        tabTraffic = findViewById(R.id.tab_traffic);
        tabServer = findViewById(R.id.tab_server);

        etSshHost = f(R.id.et_ssh_host); etSshPort = f(R.id.et_ssh_port);
        etSshUser = f(R.id.et_ssh_user); etSshPass = f(R.id.et_ssh_pass);
        etServerAddr = f(R.id.et_server_addr); etRestartMin = f(R.id.et_restart_min);
        etServerPass = f(R.id.et_server_pass);
        ddServerMethod = findViewById(R.id.dd_server_method);
        ddServerMethod.setSimpleItems(new String[]{"both", "post", "get"});
        btnDeploy = findViewById(R.id.btn_deploy);
        btnCheck = findViewById(R.id.btn_check);
        btnUninstall = findViewById(R.id.btn_uninstall);
        btnAdmin = findViewById(R.id.btn_admin);
        btnGenKey = findViewById(R.id.btn_gen_key);
        deployProgress = findViewById(R.id.deploy_progress);
        tvDeploy = findViewById(R.id.tv_deploy);

        populate(Config.load(this));
        renderLogs();
        renderStats(TunState.stats());
        handleShareIntent(getIntent()); // открытие по ссылке cdn://…

        BottomNavigationView bn = findViewById(R.id.bottom_nav);
        bn.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            tabTunnel.setVisibility(id == R.id.nav_tunnel ? View.VISIBLE : View.GONE);
            tabServer.setVisibility(id == R.id.nav_server ? View.VISIBLE : View.GONE);
            tabTraffic.setVisibility(id == R.id.nav_traffic ? View.VISIBLE : View.GONE);
            if (id == R.id.nav_traffic) renderLogs();
            return true;
        });

        btnToggle.setOnClickListener(v -> {
            if (busyOrUp()) stopVpn(); else startVpn();
        });
        btnClear.setOnClickListener(v -> { TunState.clear(); tvLog.setText(""); });
        btnDeploy.setOnClickListener(v -> startDeploy());
        btnCheck.setOnClickListener(v -> checkServer());
        btnUninstall.setOnClickListener(v -> uninstallServer());
        btnAdmin.setOnClickListener(v -> openAdmin());
        btnGenKey.setOnClickListener(v -> etServerPass.setText(randomKey()));
        btnImport.setOnClickListener(v -> importLink(etLink.getText() == null ? "" : etLink.getText().toString()));
        btnPaste.setOnClickListener(v -> pasteLink());
        btnWipe.setOnClickListener(v -> wipeAll());
        hdrManual.setOnClickListener(v -> {
            boolean show = boxManual.getVisibility() != View.VISIBLE;
            boxManual.setVisibility(show ? View.VISIBLE : View.GONE);
            chevManual.setText(show ? "▾" : "▸");
        });
        hdrAdvanced.setOnClickListener(v -> {
            boolean show = boxAdvanced.getVisibility() != View.VISIBLE;
            boxAdvanced.setVisibility(show ? View.VISIBLE : View.GONE);
            chevAdvanced.setText(show ? "▾" : "▸");
        });

        maybeAskNotif();
    }

    @Override protected void onResume() {
        super.onResume();
        TunState.setListener(this);
        onPhase(TunState.phase(), TunState.phaseDetail());
        onRunningChanged(TunState.isRunning());
        renderStats(TunState.stats());
    }

    @Override protected void onPause() {
        super.onPause();
        TunState.setListener(null);
        save(); // persist fields whenever the user leaves the screen
    }

    // ---------- config <-> UI ----------

    private void populate(Config c) {
        etIp.setText(c.ip);
        etHost.setText(c.host);
        etPassword.setText(c.password);
        etPort.setText(String.valueOf(c.port));
        etConns.setText(String.valueOf(c.conns));
        etDns.setText(c.dns);
        etMtu.setText(String.valueOf(c.mtu));
        swUdp.setChecked(c.udp);
        swBlockAaaa.setChecked(c.blockAAAA);
        swDebug.setChecked(c.debug);
        ddMethod.setText("get".equalsIgnoreCase(c.method) ? "get" : "post", false);
        ddTransport.setText("stream".equalsIgnoreCase(c.transport) ? "stream" : "chunked", false);
        swFastopen.setChecked(c.fastopen);
        etSshHost.setText(c.sshHost);
        renderProfile(c);
        etSshPort.setText(String.valueOf(c.sshPort));
        etSshUser.setText(c.sshUser);
        etSshPass.setText(c.sshPass);
        etServerAddr.setText(c.serverAddr);
        etServerPass.setText(c.serverPassword);
        etRestartMin.setText(String.valueOf(c.restartMin));
        ddServerMethod.setText(c.serverMethod == null ? "both" : c.serverMethod, false);
    }

    /**
     * Собирает конфиг из полей поверх сохранённого: поля, которых нет на экране
     * (удостоверение ссылки, SSH-ключ, host/ip для выпуска ссылок), должны
     * пережить сохранение — иначе вставленная ссылка теряет удостоверение и
     * клиент снова начинает требовать пароль.
     */
    private Config collect() {
        Config c = Config.load(this);
        c.ip = txt(etIp, c.ip);
        c.host = txt(etHost, c.host);
        c.password = etPassword.getText() == null ? "" : etPassword.getText().toString();
        c.port = intOf(etPort, c.port);
        c.conns = intOf(etConns, c.conns);
        c.dns = txt(etDns, c.dns);
        c.mtu = intOf(etMtu, c.mtu);
        c.udp = swUdp.isChecked();
        c.blockAAAA = swBlockAaaa.isChecked();
        c.debug = swDebug.isChecked();
        c.method = ddMethod.getText() != null && ddMethod.getText().toString().trim().equalsIgnoreCase("get") ? "get" : "post";
        c.transport = ddTransport.getText() != null && ddTransport.getText().toString().trim().equalsIgnoreCase("stream") ? "stream" : "chunked";
        c.fastopen = swFastopen.isChecked();
        c.sshHost = etSshHost.getText() == null ? "" : etSshHost.getText().toString().trim();
        c.sshPort = intOf(etSshPort, c.sshPort);
        c.sshUser = txt(etSshUser, c.sshUser);
        c.sshPass = etSshPass.getText() == null ? "" : etSshPass.getText().toString();
        c.serverAddr = txt(etServerAddr, c.serverAddr);
        c.restartMin = intOf(etRestartMin, 0);
        c.serverMethod = ddServerMethod.getText() == null ? "both" : ddServerMethod.getText().toString().trim();
        c.serverPassword = etServerPass.getText() == null ? "" : etServerPass.getText().toString();
        return c;
    }

    private void save() { collect().save(this); }

    // ---------- start / stop ----------

    private void startVpn() {
        save();
        Config c = collect();
        if (c.host == null || c.host.trim().isEmpty() || c.ip == null || c.ip.trim().isEmpty()) {
            tvProfile.setText("Сервер не задан — вставьте ссылку cdn:// или заполните «Ручную настройку»");
            toast("Сначала вставьте ссылку или заполните адрес сервера");
            return;
        }
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);
        } else {
            onActivityResult(REQ_VPN, RESULT_OK, null);
        }
    }

    private void stopVpn() {
        Intent i = new Intent(this, TunVpnService.class).setAction(TunVpnService.ACTION_STOP);
        startService(i);
    }

    @Override
    protected void onActivityResult(int req, int res, @Nullable Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_VPN && res == RESULT_OK) {
            Config c = collect();
            Intent i = new Intent(this, TunVpnService.class).setAction(TunVpnService.ACTION_START);
            c.toIntent(i);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i);
            else startService(i);
            TunState.setPhase(TunState.STARTING, "запуск…");
        } else if (req == REQ_VPN) {
            TunState.log("[ui] запрос VPN отклонён пользователем");
        }
    }


    // ---------- server deploy ----------

    private final DeployManager.Cb NOOP_CB = new DeployManager.Cb() {
        public void step(int i, int t, String n, String st, String d) {}
        public void done(boolean ok, String s) {}
    };

    private void startDeploy() {
        Config c = collect(); c.save(this);
        if (c.sshHost == null || c.sshHost.isEmpty()) { tvDeploy.setText("Укажите адрес VPS."); return; }
        if (c.serverPassword == null || c.serverPassword.isEmpty()) {
            // Ключ не придумывают руками — генерируем и показываем, что получилось.
            c.serverPassword = randomKey();
            etServerPass.setText(c.serverPassword);
            c.save(this);
            tvDeploy.setText("Мастер-ключ сервера сгенерирован: " + c.serverPassword + "\n\n");
        }
        if (deploying) return;
        deploying = true; setDeployBusy(true);
        tvDeploy.setText("→ Развёртывание на " + c.sshUser + "@" + c.sshHost + ":" + c.sshPort + "\n\n");
        new DeployManager(this, c, new DeployManager.Cb() {
            public void step(int idx, int total, String name, String state, String detail) {
                runOnUiThread(() -> {
                    String mark = state.equals("ok") ? "✓" : state.equals("fail") ? "✗" : "…";
                    appendDeploy(mark + " [" + (idx + 1) + "/" + total + "] " + name
                            + (detail == null || detail.isEmpty() ? "" : " — " + detail) + "\n");
                });
            }
            public void done(boolean ok, String summary) {
                runOnUiThread(() -> {
                    appendDeploy("\n" + (ok ? "✓ " : "✗ ") + summary + "\n");
                    deploying = false; setDeployBusy(false);
                });
            }
        }).start();
    }

    private void checkServer() {
        Config c = collect(); c.save(this);
        if (c.sshHost == null || c.sshHost.isEmpty()) { tvDeploy.setText("Укажите адрес VPS."); return; }
        setDeployBusy(true);
        tvDeploy.setText("→ Проверка статуса…\n");
        new DeployManager(this, c, NOOP_CB).checkServer((active, text) ->
                runOnUiThread(() -> { tvDeploy.setText(text); setDeployBusy(false); }));
    }

    private void uninstallServer() {
        Config c = collect(); c.save(this);
        if (c.sshHost == null || c.sshHost.isEmpty()) { tvDeploy.setText("Укажите адрес VPS."); return; }
        new AlertDialog.Builder(this)
                .setTitle("Удалить сервер?")
                .setMessage("Остановит и удалит сервис и бинарь с VPS.")
                .setPositiveButton("Удалить", (d, w) -> {
                    setDeployBusy(true);
                    tvDeploy.setText("→ Удаление…\n\n");
                    new DeployManager(this, c, new DeployManager.Cb() {
                        public void step(int idx, int total, String name, String state, String detail) {
                            runOnUiThread(() -> appendDeploy((state.equals("ok") ? "✓ " : state.equals("fail") ? "✗ " : "… ")
                                    + name + (detail == null || detail.isEmpty() ? "" : " — " + detail) + "\n"));
                        }
                        public void done(boolean ok, String summary) {
                            runOnUiThread(() -> { appendDeploy("\n" + summary + "\n"); setDeployBusy(false); });
                        }
                    }).uninstall();
                })
                .setNegativeButton("Отмена", null)
                .show();
    }

    /** Случайный мастер-ключ сервера: выдумывать его руками незачем. */
    private static String randomKey() {
        final String abc = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 24; i++) b.append(abc.charAt(rnd.nextInt(abc.length())));
        return b.toString();
    }

    /** Проверяет SSH и открывает панель управления сервером. */
    private void openAdmin() {
        Config c = collect(); c.save(this);
        if (c.sshHost == null || c.sshHost.isEmpty()) { tvDeploy.setText("Укажите адрес VPS."); return; }
        setDeployBusy(true);
        tvDeploy.setText("→ Подключение к серверу…\n");
        // Панель открываем, даже если сервис не отвечает: внутри видно, что
        // именно не так, и оттуда же можно перезапустить сервер.
        new DeployManager(this, c, NOOP_CB).checkServer((active, text) -> runOnUiThread(() -> {
            setDeployBusy(false);
            tvDeploy.setText(active ? "✓ Подключено — открываю управление…"
                    : "Сервис не активен, открываю панель — подробности там.\n\n" + text);
            startActivity(new Intent(this, AdminActivity.class));
        }));
    }

    private void setDeployBusy(boolean b) {
        deployProgress.setVisibility(b ? View.VISIBLE : View.GONE);
        btnDeploy.setEnabled(!b); btnCheck.setEnabled(!b); btnUninstall.setEnabled(!b);
        if (btnAdmin != null) btnAdmin.setEnabled(!b);
    }

    private void appendDeploy(String s) { tvDeploy.append(s); }

    // ---------- ссылка cdn:// ----------

    /** Приложение открыли по ссылке cdn://… — подставляем её в поле импорта. */
    private void handleShareIntent(Intent i) {
        if (i == null || i.getData() == null) return;
        String link = i.getData().toString();
        if (!link.toLowerCase().startsWith("cdn:")) return;
        etLink.setText(link);
        importLink(link);
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleShareIntent(intent);
    }

    /** Разбирает ссылку и подставляет настройки в поля (имя клиента остаётся своё). */
    private void importLink(String link) {
        if (link == null || link.trim().isEmpty()) {
            toast("Вставьте ссылку cdn://…");
            return;
        }
        Config c = collect();
        String label;
        try {
            label = ShareLink.decodeInto(link.trim(), c);
        } catch (ShareLink.BadLink e) {
            tvProfile.setText("✗ " + e.getMessage());
            toast(e.getMessage());
            return;
        }
        if (!label.isEmpty()) c.shareLabel = label;
        c.save(this);
        populate(c);
        etLink.setText("");
        etPassword.setText(c.password); // у ссылок нового образца он пуст — и не нужен
        String what = label.isEmpty() ? c.host : label + " · " + c.host;
        tvProfile.setText("✓ Импортировано: " + what);
        TunState.log("[ui] импортирована ссылка: " + what);
        toast("Настройки импортированы");
    }

    private void pasteLink() {
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        ClipData clip = cm == null ? null : cm.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) { toast("Буфер обмена пуст"); return; }
        CharSequence t = clip.getItemAt(0).coerceToText(this);
        etLink.setText(t == null ? "" : t.toString().trim());
    }

    /** Полностью стирает сохранённые настройки: ни адресов, ни паролей. */
    private void wipeAll() {
        new AlertDialog.Builder(this)
                .setTitle("Стереть все настройки?")
                .setMessage("Ссылка, адрес сервера, мастер-ключ и данные VPS будут удалены с телефона.")
                .setPositiveButton("Стереть", (d, w) -> {
                    Config.wipe(this);
                    Config fresh = new Config();
                    populate(fresh);
                    fresh.save(this);
                    TunState.log("[ui] настройки стёрты");
                    toast("Настройки стёрты");
                })
                .setNegativeButton("Отмена", null)
                .show();
    }

    /** Строка под полями импорта: какой сервер сейчас настроен. */
    private void renderProfile(Config c) {
        if (c.host == null || c.host.isEmpty()) {
            tvProfile.setText("Сервер не задан — вставьте ссылку или откройте «Ручная настройка»");
            return;
        }
        String label = (c.shareLabel == null || c.shareLabel.isEmpty()) ? "" : c.shareLabel + " · ";
        tvProfile.setText("Сервер: " + label + c.host + " (" + c.ip + ")");
    }

    private static String agoPhrase(long tSec) {
        String a = ago(tSec);
        return a.equals("только что") ? a : a + " назад";
    }

    /** «5 мин», «2 ч», «3 дн» — сколько прошло с момента unix-времени t. */
    private static String ago(long tSec) {
        long d = System.currentTimeMillis() / 1000 - tSec;
        if (d < 60) return "только что";
        if (d < 3600) return (d / 60) + " мин";
        if (d < 86400) return (d / 3600) + " ч";
        return (d / 86400) + " дн";
    }

    private int dp(int v) { return Math.round(getResources().getDisplayMetrics().density * v); }

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }

    // ---------- TunState.Listener ----------

    /**
     * Туннель поднят или как раз поднимается? Фазы отказа (сервер не принял ключ
     * или ссылку) сюда не входят: там останавливать уже нечего, и кнопка должна
     * снова предлагать запуск, а не заставлять жать «Остановить» впустую.
     */
    private boolean busyOrUp() {
        if (TunState.isRunning()) return true;
        String p = TunState.phase();
        return TunState.STARTING.equals(p) || TunState.CONNECTING.equals(p)
                || TunState.CONNECTED.equals(p);
    }

    @Override public void onRunningChanged(boolean running) {
        btnToggle.setText(busyOrUp() ? "Остановить VPN" : "Запустить VPN");
    }

    @Override public void onLog(String line) {
        if (tabTraffic.getVisibility() == View.VISIBLE) {
            tvLog.append(line + "\n");
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        }
    }

    @Override public void onPhase(String phase, String detail) {
        String label; int color;
        switch (phase) {
            case TunState.CONNECTED:    label = "Подключено";       color = 0xFF9FB86A; break;
            case TunState.CONNECTING:   label = "Подключение…";     color = 0xFFC7A34E; break;
            case TunState.STARTING:     label = "Запуск…";          color = 0xFFC7A34E; break;
            case TunState.NO_ROUTE:     label = "Нет маршрута";     color = 0xFFD0674A; break;
            case TunState.AUTH_FAIL:    label = "Неверный ключ";    color = 0xFFD0674A; break;
            case TunState.ERROR:        label = "Ошибка";           color = 0xFFD0674A; break;
            case TunState.LINK_USED:    label = "Ссылка занята";    color = 0xFFD0674A; break;
            case TunState.LINK_REVOKED: label = "Ссылка отозвана";  color = 0xFFD0674A; break;
            case TunState.LINK_GONE:    label = "Ссылки больше нет"; color = 0xFFD0674A; break;
            case TunState.LINK_BAD:     label = "Ссылка не принята"; color = 0xFFD0674A; break;
            default:                    label = "Отключено";        color = 0xFFB9A588; break;
        }
        tvStatus.setText(label);
        tvStatus.setTextColor(color);
        tvStatusDetail.setText(detail == null || detail.isEmpty()
                ? "Вставьте ссылку cdn:// и нажмите «Запустить VPN»" : detail);
        tvConn.setText("● " + label.toLowerCase());
        tvConn.setTextColor(color);

        boolean busy = phase.equals(TunState.STARTING) || phase.equals(TunState.CONNECTING);
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        onRunningChanged(TunState.isRunning());
    }

    @Override public void onStats(TunState.Stats s) {
        renderStats(s);
    }

    private void renderStats(TunState.Stats s) {
        if (s == null) return;
        tvDownTotal.setText(human(s.down));
        tvDownRate.setText(human(s.downRate) + "/s");
        tvUpTotal.setText(human(s.up));
        tvUpRate.setText(human(s.upRate) + "/s");
        tvConns.setText(String.valueOf(s.conns) + "  (Σ" + s.total + ")");
        tvUdp.setText(human(s.udpDown) + " / " + human(s.udpUp));
        tvRtt.setText(s.rtt > 0 ? s.rtt + " ms" : "— ms");
    }

    private void renderLogs() {
        StringBuilder sb = new StringBuilder();
        for (String l : TunState.snapshot()) sb.append(l).append('\n');
        tvLog.setText(sb.toString());
        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    // ---------- helpers ----------

    private void maybeAskNotif() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
        }
    }

    private static String human(double b) {
        if (b >= 1e9) return String.format("%.2f GB", b / 1e9);
        if (b >= 1e6) return String.format("%.2f MB", b / 1e6);
        if (b >= 1e3) return String.format("%.1f KB", b / 1e3);
        return String.format("%.0f B", b);
    }

    private <T extends View> T f(int id) { return findViewById(id); }

    private static String txt(TextInputEditText e, String dflt) {
        if (e.getText() == null) return dflt;
        String s = e.getText().toString().trim();
        return s.isEmpty() ? dflt : s;
    }

    private static int intOf(TextInputEditText e, int dflt) {
        try { return Integer.parseInt(txt(e, String.valueOf(dflt))); }
        catch (NumberFormatException ex) { return dflt; }
    }
}
