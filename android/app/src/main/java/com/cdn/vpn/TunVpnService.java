package com.cdn.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * VpnService that:
 *   1. launches the tunnel client (libtun.so, main.go -client) as a child
 *      process exposing a local SOCKS5 proxy;
 *   2. establishes a TUN interface capturing the whole device;
 *   3. feeds TUN packets to the SOCKS5 via the embedded tun2socks engine.
 *
 * The password is passed to the client via -password; if the server rejects it
 * (403), the client prints "STATUS authfail" and exits, so no tunnel is set up.
 */
public class TunVpnService extends VpnService {

    public static final String ACTION_START = "com.cdn.vpn.START";
    public static final String ACTION_STOP  = "com.cdn.vpn.STOP";

    private static final String CHANNEL = "cdntunnel";
    private static final int NOTIF_ID = 1;

    private ParcelFileDescriptor vpnPfd;
    private Process tunProc;
    private Thread worker;
    private Thread prober;
    private volatile boolean engineUp = false;
    private volatile boolean stopping = false;
    private volatile boolean authFail = false;
    private volatile boolean linkDead = false; // ссылку удалили, отозвали или заняли — VPN гасим
    private volatile int socksPort = 8090;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) {
            stopEverything();
            return START_NOT_STICKY;
        }
        final Config cfg = (intent != null) ? Config.fromIntent(intent) : Config.load(this);
        TunState.setPhase(TunState.STARTING, "запуск туннеля…");
        startForegroundNotif();
        if (worker != null && worker.isAlive()) {
            TunState.log("[svc] уже запускается/работает");
            return START_STICKY;
        }
        worker = new Thread(() -> bringUp(cfg), "tun-bringup");
        worker.start();
        return START_STICKY;
    }

    private void bringUp(Config cfg) {
        stopping = false;
        authFail = false;
        linkDead = false;
        socksPort = cfg.port;
        try {
            TunState.log("[svc] запуск бинарника туннеля…");
            startTunnelProcess(cfg);

            // SOCKS открывается ТОЛЬКО после успешного hello: если сервер отказал,
            // клиент печатает STATUS и выходит, а фазу уже выставил handleStatusLine.
            if (!waitForSocks("127.0.0.1", cfg.port, 12000)) {
                if (authFail || linkDead) {
                    TunState.log("[svc] сервер отказал в доступе — подключение прервано");
                } else {
                    TunState.setPhase(TunState.ERROR, "SOCKS не поднялся (сервер недоступен?)");
                    TunState.log("[svc] ОШИБКА: SOCKS " + cfg.port + " не поднялся");
                }
                stopEverything();
                return;
            }
            TunState.log("[svc] SOCKS поднят на 127.0.0.1:" + cfg.port);

            TunState.setPhase(TunState.CONNECTING, "проверка маршрута через туннель…");
            boolean routed = false;
            long linkDeadline = System.currentTimeMillis() + 12000;
            int tries = 0;
            while (System.currentTimeMillis() < linkDeadline && !stopping) {
                if (probeThroughSocks(cfg.port)) { routed = true; break; }
                if (authFail || linkDead) { // фазу уже выставил handleStatusLine
                    stopEverything();
                    return;
                }
                TunState.setPhase(TunState.CONNECTING, "проверка маршрута… (" + (++tries) + ")");
                sleep(2000);
            }
            if (stopping) return;

            Builder b = new Builder();
            b.setSession("CDN Tunnel");
            b.setMtu(cfg.mtu);
            b.addAddress("10.0.0.2", 32);
            b.addRoute("0.0.0.0", 0);
            try {
                b.addAddress("fd00::2", 128);
                b.addRoute("::", 0);
            } catch (Throwable t) {
                TunState.log("[svc] ipv6 маршрут пропущен: " + t.getMessage());
            }
            if (cfg.dns != null && !cfg.dns.isEmpty()) {
                b.addDnsServer(cfg.dns);
            }
            // Наш собственный трафик (клиент туннеля к CDN) должен идти в обход VPN.
            try {
                b.addDisallowedApplication(getPackageName());
            } catch (Exception e) {
                TunState.log("[svc] disallow self не удался: " + e.getMessage());
            }
            b.setBlocking(false);

            vpnPfd = b.establish();
            if (vpnPfd == null) {
                TunState.log("[svc] ОШИБКА: establish() вернул null");
                stopEverything();
                return;
            }
            int fd = vpnPfd.getFd();
            TunState.log("[svc] TUN поднят, fd=" + fd + ", старт tun2socks…");

            String loglevel = cfg.debug ? "debug" : "warn";
            t2smobile.T2smobile.start((long) fd, "127.0.0.1:" + cfg.port, (long) cfg.mtu,
                    loglevel, cfg.dns == null ? "" : cfg.dns, cfg.blockAAAA);
            engineUp = true;

            TunState.setRunning(true);
            TunState.setPhase(routed ? TunState.CONNECTED : TunState.CONNECTING,
                    routed ? "трафик проверен сквозь туннель" : "поднимаем VPN, проверяем маршрут…");
            TunState.log("[svc] VPN активен — мониторинг связи…");
            startProber();
        } catch (Throwable t) {
            TunState.log("[svc] ОШИБКА: " + t);
            TunState.setPhase(TunState.ERROR, String.valueOf(t.getMessage()));
            stopEverything();
        }
    }

    private void startProber() {
        prober = new Thread(() -> {
            int fails = 0;
            boolean everOk = false;
            while (engineUp && !stopping) {
                boolean ok = probeThroughSocks(socksPort);
                if (ok) {
                    fails = 0; everOk = true;
                    TunState.setPhase(TunState.CONNECTED, "трафик проверен сквозь туннель");
                    sleep(15000);
                } else {
                    fails++;
                    if (!everOk && fails < 4) {
                        TunState.setPhase(TunState.CONNECTING, "ожидание сервера… (" + fails + ")");
                    } else {
                        TunState.setPhase(TunState.NO_ROUTE, "нет трафика через туннель");
                    }
                    sleep(4000);
                }
            }
        }, "tun-prober");
        prober.setDaemon(true);
        prober.start();
    }

    /** SOCKS5 CONNECT to a known host and read an HTTP 204; true = whole path works. */
    private boolean probeThroughSocks(int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), 1500);
            s.setSoTimeout(6000);
            java.io.OutputStream o = s.getOutputStream();
            java.io.InputStream in = s.getInputStream();
            o.write(new byte[]{0x05, 0x01, 0x00});
            o.flush();
            byte[] r = new byte[2];
            if (in.read(r) != 2 || r[0] != 0x05 || r[1] != 0x00) return false;
            String host = "connectivitycheck.gstatic.com";
            byte[] hb = host.getBytes("US-ASCII");
            java.io.ByteArrayOutputStream req = new java.io.ByteArrayOutputStream();
            req.write(new byte[]{0x05, 0x01, 0x00, 0x03});
            req.write(hb.length);
            req.write(hb);
            req.write((80 >> 8) & 0xff);
            req.write(80 & 0xff);
            o.write(req.toByteArray());
            o.flush();
            byte[] rep = new byte[4];
            if (in.read(rep) != 4 || rep[1] != 0x00) return false;
            int atyp = rep[3];
            int skip = (atyp == 0x01) ? 4 + 2 : (atyp == 0x04) ? 16 + 2 : (atyp == 0x03) ? (in.read() + 2) : 0;
            byte[] junk = new byte[Math.max(0, skip)];
            int got = 0;
            while (got < junk.length) { int k = in.read(junk, got, junk.length - got); if (k < 0) break; got += k; }
            String httpReq = "GET /generate_204 HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            o.write(httpReq.getBytes("US-ASCII"));
            o.flush();
            byte[] buf = new byte[64];
            int n = in.read(buf);
            if (n <= 0) return false;
            String status = new String(buf, 0, n, "US-ASCII");
            return status.startsWith("HTTP/1.1 2") || status.startsWith("HTTP/1.0 2") || status.contains(" 204 ");
        } catch (Exception e) {
            return false;
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    private void startTunnelProcess(Config cfg) throws Exception {
        String bin = getApplicationInfo().nativeLibraryDir + "/libtun.so";
        List<String> cmd = new ArrayList<>();
        cmd.add(bin);
        cmd.add("-client");
        cmd.add("-ip"); cmd.add(cfg.ip);
        cmd.add("-host"); cmd.add(cfg.host);
        // По ссылке ходим с её удостоверением, у владельца — с мастер-паролем.
        if (cfg.cred != null && !cfg.cred.isEmpty()) {
            cmd.add("-cred"); cmd.add(cfg.cred);
            cmd.add("-device"); cmd.add(deviceFingerprint());
        } else if (cfg.password != null && !cfg.password.isEmpty()) {
            cmd.add("-password"); cmd.add(cfg.password);
        }
        cmd.add("-listen"); cmd.add("127.0.0.1:" + cfg.port);
        cmd.add("-conns"); cmd.add(String.valueOf(cfg.conns));
        cmd.add("-udp=" + cfg.udp);
        cmd.add("-method"); cmd.add(cfg.method);
        cmd.add("-transport"); cmd.add(cfg.transport);
        cmd.add("-fastopen=" + cfg.fastopen);
        cmd.add("-stats");

        TunState.log("[svc] exec: libtun.so -client -ip " + cfg.ip + " -host " + cfg.host
                + " -listen 127.0.0.1:" + cfg.port + " -conns " + cfg.conns + " -udp=" + cfg.udp
                + " -method " + cfg.method + " -transport " + cfg.transport + " -fastopen=" + cfg.fastopen + "\n"
                + (cfg.cred != null && !cfg.cred.isEmpty() ? " -cred ****" : "")
                + (cfg.password != null && !cfg.password.isEmpty() ? " -password ****" : ""));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.directory(getFilesDir());
        final Process proc = pb.start();
        tunProc = proc;

        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                String line;
                while ((line = r.readLine()) != null) {
                    handleTunLine(line);
                }
            } catch (Exception ignored) {
            }
            try {
                int code = proc.waitFor();
                TunState.log("[tun] процесс завершился, код=" + code);
                if (engineUp && !stopping) stopEverything();
            } catch (InterruptedException ignored) {}
        }, "tun-log");
        reader.setDaemon(true);
        reader.start();
    }

    /**
     * Отпечаток устройства для привязки ссылки: ANDROID_ID (у каждого приложения
     * на каждом устройстве свой и стабильный) в виде укороченного хеша — наружу
     * уходит только он, сам идентификатор не светится.
     */
    private String deviceFingerprint() {
        String raw = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        if (raw == null || raw.isEmpty()) raw = Build.MODEL + "/" + Build.FINGERPRINT;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(("cdn-tunnel/device/v1:" + raw).getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", h[i]));
            return sb.toString();
        } catch (Exception e) {
            return "android";
        }
    }

    /** Parse a line from the tunnel: STATS (traffic), STATUS (auth/link) or a log line. */
    private void handleTunLine(String line) {
        if (line == null) return;
        String l = line.trim();
        if (l.isEmpty()) return;

        if (l.startsWith("STATS ")) {
            parseStats(l);
            return; // don't spam the log with per-second stats
        }
        if (l.startsWith("STATUS ")) {
            handleStatusLine(l.substring(7).trim());
            TunState.log("[tun] " + l);
            return;
        }
        String low = l.toLowerCase();
        if (low.contains("403") || low.contains("мастер-ключ")) {
            authFail = true;
        }
        TunState.log("[tun] " + l);
    }

    /**
     * Строка "STATUS ..." — приговор сервера по нашему доступу. Всё, что означает
     * «этой ссылкой больше нельзя», гасит VPN: владелец мог удалить или отозвать
     * ссылку уже после подключения, и клиент узнаёт об этом на очередном пинге.
     */
    private void handleStatusLine(String s) {
        switch (s) {
            case "authfail":
                authFail = true;
                TunState.setPhase(TunState.AUTH_FAIL, "сервер не принял мастер-ключ");
                break;
            case "linkused":
                linkDead = true;
                TunState.setPhase(TunState.LINK_USED, "ссылка занята другим устройством");
                TunState.log("[tun] ⚠ эта ссылка уже используется на другом устройстве");
                break;
            case "linkrevoked":
                linkDead = true;
                TunState.setPhase(TunState.LINK_REVOKED, "владелец отозвал эту ссылку");
                TunState.log("[tun] ⛔ ссылка отозвана владельцем сервера");
                break;
            case "linkgone":
                linkDead = true;
                TunState.setPhase(TunState.LINK_GONE, "владелец удалил эту ссылку");
                TunState.log("[tun] ⛔ ссылки больше нет на сервере — попросите новую");
                break;
            case "linkbad":
                linkDead = true;
                TunState.setPhase(TunState.LINK_BAD, "сервер не принял эту ссылку");
                TunState.log("[tun] ⛔ сервер не принял ссылку — возможно, она от другого сервера");
                break;
            default:
                return;
        }
        // Доступа больше нет: не держим VPN поднятым, иначе телефон остался бы
        // без интернета с мёртвым туннелем.
        if (linkDead && engineUp && !stopping) stopEverything();
    }

    private void parseStats(String l) {
        TunState.Stats st = new TunState.Stats();
        for (String tok : l.substring(6).trim().split("\\s+")) {
            int eq = tok.indexOf('=');
            if (eq <= 0) continue;
            String k = tok.substring(0, eq);
            long v;
            try { v = (long) Double.parseDouble(tok.substring(eq + 1)); }
            catch (NumberFormatException e) { continue; }
            switch (k) {
                case "down": st.down = v; break;
                case "up": st.up = v; break;
                case "udpDown": st.udpDown = v; break;
                case "udpUp": st.udpUp = v; break;
                case "conns": st.conns = v; break;
                case "total": st.total = v; break;
                case "downRate": st.downRate = v; break;
                case "upRate": st.upRate = v; break;
                case "rtt": st.rtt = v; break;
            }
        }
        TunState.setStats(st);
    }

    private boolean waitForSocks(String host, int port, int timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline && !stopping) {
            if (authFail || linkDead) return false;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), 300);
                return true;
            } catch (Exception e) {
                try { Thread.sleep(200); } catch (InterruptedException ignored) { return false; }
            }
        }
        return false;
    }

    private synchronized void stopEverything() {
        stopping = true;
        if (engineUp) {
            engineUp = false;
            try { t2smobile.T2smobile.stop(); } catch (Throwable t) {
                TunState.log("[svc] стоп движка: " + t);
            }
        }
        if (tunProc != null) {
            try { tunProc.destroy(); } catch (Throwable ignored) {}
            tunProc = null;
        }
        if (vpnPfd != null) {
            try { vpnPfd.close(); } catch (Throwable ignored) {}
            vpnPfd = null;
        }
        TunState.setRunning(false);
        // Причину отказа (нет ссылки / отозвана / занята) оставляем на экране.
        if (!authFail && !linkDead) TunState.setPhase(TunState.DISCONNECTED, "");
        TunState.log("[svc] остановлено.");
        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onRevoke() {
        TunState.log("[svc] VPN отозван системой.");
        stopEverything();
    }

    @Override
    public void onDestroy() {
        stopEverything();
        super.onDestroy();
    }

    private void startForegroundNotif() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL, "CDN Tunnel", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("Статус VPN-туннеля");
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);

        Intent stop = new Intent(this, TunVpnService.class).setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE);

        Notification n = new Notification.Builder(this, CHANNEL)
                .setContentTitle("CDN Tunnel")
                .setContentText("Туннель активен — нажмите, чтобы открыть, или Стоп")
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentIntent(pi)
                .addAction(new Notification.Action.Builder(null, "Стоп", stopPi).build())
                .setOngoing(true)
                .build();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIF_ID, n);
        }
    }
}
