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

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
    private volatile boolean userLimit = false; // сервер полон (-users): клиент получил 429
    private volatile boolean linkUsed = false;  // ссылка занята другим устройством (409)
    private volatile boolean banned = false;    // клиент заблокирован владельцем (403 banned)
    private volatile int socksPort = 8090;
    private volatile long lastUsers = -1; // последнее «занято» из строк USERS (-1 = ещё не знаем)

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
        userLimit = false;
        linkUsed = false;
        banned = false;
        lastUsers = -1;
        socksPort = cfg.port;
        try {
            TunState.log("[svc] запуск бинарника туннеля…");
            startTunnelProcess(cfg);

            // SOCKS открывается ТОЛЬКО после успешного hello (верный пароль).
            // Если пароль неверный — процесс печатает "STATUS authfail" и выходит.
            if (!waitForSocks("127.0.0.1", cfg.port, 12000)) {
                if (authFail) {
                    TunState.setPhase(TunState.AUTH_FAIL, "сервер отклонил пароль");
                    TunState.log("[svc] неверный пароль — подключение отклонено");
                } else if (linkUsed) {
                    TunState.setPhase(TunState.LINK_USED, "ссылка уже использована на другом устройстве");
                    TunState.log("[svc] ссылка занята другим устройством");
                } else if (banned) {
                    TunState.setPhase(TunState.BANNED, "владелец сервера заблокировал этого клиента");
                } else if (userLimit) {
                    TunState.setPhase(TunState.USER_LIMIT, "достигнуто максимальное число подключений");
                    TunState.log("[svc] сервер занят: лимит одновременных клиентов исчерпан");
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
                if (authFail) {
                    TunState.setPhase(TunState.AUTH_FAIL, "сервер отклонил пароль");
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
        if (cfg.name != null && !cfg.name.trim().isEmpty()) {
            cmd.add("-name"); cmd.add(cfg.name.trim()); // под этим именем клиент виден в списке
        }
        cmd.add("-stats");

        TunState.log("[svc] exec: libtun.so -client -ip " + cfg.ip + " -host " + cfg.host
                + " -listen 127.0.0.1:" + cfg.port + " -conns " + cfg.conns + " -udp=" + cfg.udp
                + " -method " + cfg.method + " -transport " + cfg.transport + " -fastopen=" + cfg.fastopen + "\n"
                + (cfg.password != null && !cfg.password.isEmpty() ? " -password ****" : " (без пароля)"));

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
        if (l.startsWith("ROSTER ")) {
            handleRosterLine(l.substring(7).trim());
            return; // список пользователей — не в журнал, а на вкладку «Юзеры»
        }
        if (l.startsWith("USERS ")) {
            handleUsersLine(l.substring(6).trim());
            return;
        }
        if (l.startsWith("STATUS ")) {
            String s = l.substring(7).trim();
            if (s.equals("authfail")) {
                authFail = true;
                TunState.setPhase(TunState.AUTH_FAIL, "сервер отклонил пароль");
            }
            if (s.equals("linkused")) {
                linkUsed = true;
                TunState.setPhase(TunState.LINK_USED, "ссылка уже использована на другом устройстве");
                TunState.log("[tun] ⚠ эта ссылка привязана к другому устройству — попросите новую");
            }
            if (s.equals("linkrevoked")) {
                linkUsed = true;
                TunState.setPhase(TunState.LINK_REVOKED, "владелец отозвал эту ссылку");
                TunState.log("[tun] ⛔ ссылка отозвана владельцем сервера");
            }
            if (s.equals("banned")) {
                banned = true;
                TunState.setPhase(TunState.BANNED, "владелец сервера заблокировал этого клиента");
                TunState.log("[tun] ⛔ клиент заблокирован на сервере");
            }
            if (s.equals("userlimit")) {
                userLimit = true;
                TunState.setPhase(TunState.USER_LIMIT, "достигнуто максимальное число подключений");
                TunState.log("[tun] ⚠ сервер занят: свободных мест нет (-users)");
            }
            TunState.log("[tun] " + l);
            return;
        }
        String low = l.toLowerCase();
        if (low.contains("403") || low.contains("неверный пароль")) {
            authFail = true;
        }
        if (low.contains("максимальное число подключений")) {
            userLimit = true;
        }
        TunState.log("[tun] " + l);
    }

    /**
     * Строка "USERS n/m" — сервер с флагом -users сообщает, сколько клиентов
     * сейчас занято из скольких. Клиент печатает её только при изменении, так
     * что журнал показывает подключения соседей в прямом эфире.
     */
    private void handleUsersLine(String v) {
        int slash = v.indexOf('/');
        if (slash <= 0) return;
        long now, max;
        try {
            now = Long.parseLong(v.substring(0, slash).trim());
            max = Long.parseLong(v.substring(slash + 1).trim());
        } catch (NumberFormatException e) {
            return;
        }
        long prev = lastUsers;
        lastUsers = now;
        TunState.setUsers(now, max);
        String line;
        if (prev < 0)        line = "👥 Подключено " + now + "/" + max;
        else if (now > prev) line = "👥 Подключился клиент — " + now + "/" + max;
        else if (now < prev) line = "👥 Клиент отключился — " + now + "/" + max;
        else                 line = "👥 " + now + "/" + max;
        TunState.log("[tun] " + line);
    }

    /**
     * Строка "ROSTER {json}" — список пользователей сервера (кто онлайн, кто нет).
     * Клиент печатает её только при изменении состава.
     */
    private void handleRosterLine(String json) {
        try {
            JSONObject o = new JSONObject(json);
            TunState.Roster r = new TunState.Roster();
            r.limit = o.optInt("limit", 0);
            r.online = o.optInt("online", 0);
            r.at = System.currentTimeMillis();
            JSONArray arr = o.optJSONArray("users");
            for (int i = 0; arr != null && i < arr.length(); i++) {
                JSONObject u = arr.optJSONObject(i);
                if (u == null) continue;
                TunState.User user = new TunState.User();
                user.name = u.optString("name", "?");
                user.online = u.optBoolean("online", false);
                user.last = u.optLong("last", 0);
                user.since = u.optLong("since", 0);
                user.seen = u.optLong("seen", 0);
                r.users.add(user);
            }
            TunState.setRoster(r);
        } catch (JSONException ignored) {
        }
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
                case "users": st.users = v; break;
                case "maxusers": st.maxUsers = v; break;
            }
        }
        TunState.setStats(st);
    }

    private boolean waitForSocks(String host, int port, int timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline && !stopping) {
            if (authFail) return false;
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
        if (!authFail) TunState.setPhase(TunState.DISCONNECTED, "");
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
