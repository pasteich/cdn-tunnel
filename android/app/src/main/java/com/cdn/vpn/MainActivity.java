package com.cdn.vpn;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

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
    private MaterialSwitch swUdp, swBlockAaaa, swDebug;
    private MaterialAutoCompleteTextView ddMethod, ddTransport;
    private MaterialSwitch swFastopen;
    private MaterialButton btnToggle, btnClear;
    private TextView tvStatus, tvStatusDetail, tvConn, tvLog, chevAdvanced;
    private TextView tvDownTotal, tvDownRate, tvUpTotal, tvUpRate, tvConns, tvUdp, tvRtt;
    private LinearProgressIndicator progress;
    private ScrollView logScroll;
    private View boxAdvanced, hdrAdvanced;
    private View tabTunnel, tabTraffic, tabLog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etIp = f(R.id.et_ip); etHost = f(R.id.et_host); etPassword = f(R.id.et_password);
        etPort = f(R.id.et_port); etConns = f(R.id.et_conns);
        etDns = f(R.id.et_dns); etMtu = f(R.id.et_mtu);
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
        logScroll = findViewById(R.id.log_scroll);
        chevAdvanced = findViewById(R.id.chev_advanced);
        boxAdvanced = findViewById(R.id.box_advanced);
        hdrAdvanced = findViewById(R.id.hdr_advanced);

        tvDownTotal = findViewById(R.id.tv_down_total);
        tvDownRate = findViewById(R.id.tv_down_rate);
        tvUpTotal = findViewById(R.id.tv_up_total);
        tvUpRate = findViewById(R.id.tv_up_rate);
        tvConns = findViewById(R.id.tv_conns);
        tvUdp = findViewById(R.id.tv_udp);
        tvRtt = findViewById(R.id.tv_rtt);

        tabTunnel = findViewById(R.id.tab_tunnel);
        tabTraffic = findViewById(R.id.tab_traffic);
        tabLog = findViewById(R.id.tab_log);

        populate(Config.load(this));
        renderLogs();
        renderStats(TunState.stats());

        BottomNavigationView bn = findViewById(R.id.bottom_nav);
        bn.setOnItemSelectedListener(item -> {
            int id = item.getItemId();
            tabTunnel.setVisibility(id == R.id.nav_tunnel ? View.VISIBLE : View.GONE);
            tabTraffic.setVisibility(id == R.id.nav_traffic ? View.VISIBLE : View.GONE);
            tabLog.setVisibility(id == R.id.nav_log ? View.VISIBLE : View.GONE);
            if (id == R.id.nav_log) renderLogs();
            return true;
        });

        btnToggle.setOnClickListener(v -> {
            boolean active = TunState.isRunning() || !TunState.DISCONNECTED.equals(TunState.phase());
            if (active) stopVpn(); else startVpn();
        });
        btnClear.setOnClickListener(v -> { TunState.clear(); tvLog.setText(""); });
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
    }

    private Config collect() {
        Config c = new Config();
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
        return c;
    }

    private void save() { collect().save(this); }

    // ---------- start / stop ----------

    private void startVpn() {
        save();
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

    // ---------- TunState.Listener ----------

    @Override public void onRunningChanged(boolean running) {
        btnToggle.setText(running || !TunState.DISCONNECTED.equals(TunState.phase())
                ? "Остановить VPN" : "Запустить VPN");
    }

    @Override public void onLog(String line) {
        if (tabLog.getVisibility() == View.VISIBLE) {
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
            case TunState.AUTH_FAIL:    label = "Неверный пароль";  color = 0xFFD0674A; break;
            case TunState.ERROR:        label = "Ошибка";           color = 0xFFD0674A; break;
            default:                    label = "Отключено";        color = 0xFFB9A588; break;
        }
        tvStatus.setText(label);
        tvStatus.setTextColor(color);
        tvStatusDetail.setText(detail == null || detail.isEmpty()
                ? "Заполните поля и нажмите «Запустить VPN»" : detail);
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
