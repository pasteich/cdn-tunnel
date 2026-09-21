package com.cdn.vpn;

import android.content.Context;
import android.content.res.AssetManager;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

/**
 * Разворачивает серверную часть туннеля на Linux-VPS по SSH: заливает нужный
 * бинарь, пишет systemd-юнит (с тем же паролем, что и клиент) и запускает его
 * с автозапуском при перезагрузке. Опционально — периодический рестарт через
 * RuntimeMaxSec. Прогресс отдаётся по шагам.
 */
public class DeployManager {

    public interface Cb {
        /** state: "run" | "ok" | "fail" */
        void step(int idx, int total, String name, String state, String detail);
        void done(boolean ok, String summary);
    }

    private static final String REMOTE_BIN = "/usr/local/bin/cdn-tunnel";
    private static final String UNIT_PATH  = "/etc/systemd/system/cdn-tunnel.service";
    private static final String SERVICE    = "cdn-tunnel";

    private static final String[] STEP_NAMES = {
            "Подключение по SSH",
            "Определение архитектуры",
            "Загрузка бинарника",
            "Запись systemd-сервиса",
            "Включение и запуск",
            "Проверка статуса",
    };

    private final Context ctx;
    private final Config cfg;
    private final Cb cb;

    public DeployManager(Context ctx, Config cfg, Cb cb) {
        this.ctx = ctx.getApplicationContext();
        this.cfg = cfg;
        this.cb = cb;
    }

    public void start()     { new Thread(this::run, "deploy").start(); }
    public void uninstall() { new Thread(this::runUninstall, "deploy-uninstall").start(); }

    public interface CheckCb { void result(boolean active, String text); }

    /** Прочитать статус сервиса + журнал, без изменений. */
    public void checkServer(CheckCb ccb) {
        new Thread(() -> {
            Session s = null;
            try {
                s = connect();
                String active  = exec(s, "systemctl is-active " + SERVICE + " 2>/dev/null", null).out.trim();
                String enabled = exec(s, "systemctl is-enabled " + SERVICE + " 2>/dev/null", null).out.trim();
                String logs = exec(s, "journalctl -u " + SERVICE + " --no-pager -n 40 2>&1 | sed 's/\\x1b\\[[0-9;]*m//g'", null).out;
                StringBuilder b = new StringBuilder();
                b.append("● статус : ").append(active.isEmpty() ? "unknown" : active)
                 .append("  (").append(enabled.isEmpty() ? "?" : enabled).append(")\n\n")
                 .append(logs.trim());
                ccb.result("active".equals(active), b.toString());
            } catch (Throwable t) {
                ccb.result(false, "Ошибка: " + t.getMessage());
            } finally {
                if (s != null) s.disconnect();
            }
        }, "deploy-check").start();
    }

    private static final String[] UNINSTALL_STEPS = {
            "Подключение по SSH", "Остановка и отключение", "Удаление бинарника и юнита",
    };

    private void runUninstall() {
        int total = UNINSTALL_STEPS.length;
        Session session = null;
        try {
            cb.step(0, total, UNINSTALL_STEPS[0], "run", cfg.sshUser + "@" + cfg.sshHost + ":" + cfg.sshPort);
            session = connect();
            cb.step(0, total, UNINSTALL_STEPS[0], "ok", "подключено");

            cb.step(1, total, UNINSTALL_STEPS[1], "run", null);
            exec(session, "systemctl disable --now " + SERVICE + " 2>/dev/null; true", null);
            cb.step(1, total, UNINSTALL_STEPS[1], "ok", "остановлен и отключён");

            cb.step(2, total, UNINSTALL_STEPS[2], "run", null);
            exec(session, "rm -f " + UNIT_PATH + " " + REMOTE_BIN + "; systemctl daemon-reload; true", null);
            cb.step(2, total, UNINSTALL_STEPS[2], "ok", "удалено");
            cb.done(true, "Сервер удалён с VPS.");
        } catch (Throwable t) {
            cb.done(false, "Ошибка: " + t.getMessage());
        } finally {
            if (session != null) session.disconnect();
        }
    }

    private void run() {
        int total = STEP_NAMES.length;
        Session session = null;
        try {
            cb.step(0, total, STEP_NAMES[0], "run", cfg.sshUser + "@" + cfg.sshHost + ":" + cfg.sshPort);
            session = connect();
            cb.step(0, total, STEP_NAMES[0], "ok", "подключено");

            cb.step(1, total, STEP_NAMES[1], "run", null);
            String uname = exec(session, "uname -m", null).out.trim();
            String arch;
            if (uname.contains("x86_64") || uname.contains("amd64")) arch = "amd64";
            else if (uname.contains("aarch64") || uname.contains("arm64")) arch = "arm64";
            else { fail(1, total, STEP_NAMES[1], "неизвестная архитектура: " + uname); return; }
            cb.step(1, total, STEP_NAMES[1], "ok", uname + " → " + arch);

            cb.step(2, total, STEP_NAMES[2], "run", "передача бинарника");
            byte[] bin = readAsset("server/cdn-tunnel-" + arch);
            exec(session, "systemctl stop " + SERVICE + " 2>/dev/null; true", null); // не text-file-busy
            Exec up = exec(session, "cat > " + REMOTE_BIN + " && chmod 755 " + REMOTE_BIN + " && echo OK", bin);
            if (up.code != 0 || !up.out.contains("OK")) { fail(2, total, STEP_NAMES[2], trim(up)); return; }
            cb.step(2, total, STEP_NAMES[2], "ok", bin.length / 1024 + " KiB → " + REMOTE_BIN);

            cb.step(3, total, STEP_NAMES[3], "run", null);
            Exec un = exec(session, "cat > " + UNIT_PATH + " && echo OK", buildUnit().getBytes("UTF-8"));
            if (un.code != 0 || !un.out.contains("OK")) { fail(3, total, STEP_NAMES[3], trim(un)); return; }
            String rst = cfg.restartMin > 0 ? (", рестарт каждые " + cfg.restartMin + " мин") : "";
            cb.step(3, total, STEP_NAMES[3], "ok", UNIT_PATH + rst);

            cb.step(4, total, STEP_NAMES[4], "run", "daemon-reload + enable --now");
            Exec en = exec(session, "systemctl daemon-reload && systemctl enable --now " + SERVICE
                    + " && systemctl restart " + SERVICE + " && echo OK", null);
            if (en.code != 0) { fail(4, total, STEP_NAMES[4], trim(en)); return; }
            cb.step(4, total, STEP_NAMES[4], "ok", "запущено, автозапуск включён");

            cb.step(5, total, STEP_NAMES[5], "run", "проверка статуса и логов");
            sleep(3500);
            String active = exec(session, "systemctl is-active " + SERVICE, null).out.trim();
            String logs = exec(session, "journalctl -u " + SERVICE + " --no-pager -n 15 2>&1", null).out;
            boolean listening = logs.contains("слушает") || logs.contains("tunnel server") || logs.contains("Приём данных");
            if ("active".equals(active) && listening) {
                cb.step(5, total, STEP_NAMES[5], "ok", "active · сервер слушает");
                cb.done(true, "Сервер запущен и слушает. Выпускайте ссылки в «Управлении сервером».");
            } else if ("active".equals(active)) {
                cb.step(5, total, STEP_NAMES[5], "ok", "active");
                cb.done(true, "Сервис active. Лог:\n" + tail(logs));
            } else {
                cb.step(5, total, STEP_NAMES[5], "fail", "is-active=" + active);
                cb.done(false, "Сервис не активен. Лог:\n" + tail(logs));
            }
        } catch (Throwable t) {
            cb.done(false, "Ошибка: " + t.getMessage());
        } finally {
            if (session != null) session.disconnect();
        }
    }

    private String buildUnit() {
        StringBuilder e = new StringBuilder();
        e.append(REMOTE_BIN).append(" -server");
        e.append(" -addr ").append(cfg.serverAddr == null || cfg.serverAddr.isEmpty() ? ":80" : cfg.serverAddr);
        e.append(" -method ").append(cfg.serverMethod == null || cfg.serverMethod.isEmpty() ? "both" : cfg.serverMethod);
        // Мастер-ключ сервера: им подписываются ссылки и открывается админка.
        String pw = cfg.serverPassword == null ? "" : cfg.serverPassword;
        if (pw != null && !pw.isEmpty()) {
            e.append(" -password \"").append(esc(pw)).append("\"");
        }

        StringBuilder u = new StringBuilder();
        u.append("[Unit]\n")
         .append("Description=CDN Tunnel (server)\n")
         .append("After=network-online.target\n")
         .append("Wants=network-online.target\n\n")
         .append("[Service]\n")
         .append("ExecStart=").append(e).append("\n")
         .append("Restart=always\n")
         .append("RestartSec=3\n");
        if (cfg.restartMin > 0) {
            u.append("RuntimeMaxSec=").append(cfg.restartMin * 60).append("\n"); // рестарт каждые N минут
        }
        u.append("User=root\n")
         .append("AmbientCapabilities=CAP_NET_BIND_SERVICE\n") // чтобы слушать :80 не под root — на всякий
         .append("LimitNOFILE=1048576\n\n")
         .append("[Install]\n")
         .append("WantedBy=multi-user.target\n");
        return u.toString();
    }

    /** Экранирование для двойных кавычек в ExecStart systemd: \\ " и $ ($$). */
    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "$$");
    }

    // ---- админка: ходим к серверу изнутри VPS (curl на localhost) ----

    public interface AdminCb { void result(boolean ok, String body); }

    /**
     * Дёргает ручку /admin… у запущенного сервера через SSH: curl на localhost,
     * мастер-пароль в заголовке. Наружу админка не светится, TLS не нужен —
     * запрос никуда из машины не уходит.
     */
    public void admin(String path, AdminCb cb2) {
        new Thread(() -> {
            Session s = null;
            try {
                s = connect();
                String pw = cfg.serverPassword == null ? "" : cfg.serverPassword;
                String port = localPort();
                // curl есть не на каждой VPS — молча падаем на wget. Всё заворачиваем
                // в sh -c: логин-шелл на сервере может быть каким угодно (fish,
                // например, не понимает if/then/fi).
                String url = "http://127.0.0.1:" + port + path;
                String hdr = "X-Tunnel-Auth: " + pw;
                String inner = "if command -v curl >/dev/null 2>&1; then"
                        + " curl -s --max-time 10 -H " + sq(hdr) + " " + sq(url) + ";"
                        + " else wget -q -O - --timeout=10 --header=" + sq(hdr) + " " + sq(url) + ";"
                        + " fi";
                String cmd = "sh -c " + sq(inner);
                Exec e = exec(s, cmd, null);
                String out = e.out == null ? "" : e.out.trim();
                cb2.result(out.startsWith("{"), out);
            } catch (Throwable t) {
                cb2.result(false, "Ошибка: " + t.getMessage());
            } finally {
                if (s != null) s.disconnect();
            }
        }, "admin-req").start();
    }

    /** Порт, на котором слушает сервер (из -addr вида ":80" или "1.2.3.4:8080"). */
    private String localPort() {
        String a = cfg.serverAddr == null ? "" : cfg.serverAddr.trim();
        int i = a.lastIndexOf(':');
        String p = i >= 0 ? a.substring(i + 1) : a;
        return p.isEmpty() ? "80" : p;
    }

    /** Оборачивает строку в одинарные кавычки для shell (с экранированием своих). */
    private static String sq(String s) {
        return "'" + (s == null ? "" : s.replace("'", "'\\''")) + "'";
    }

    private Session connect() throws Exception {
        JSch jsch = new JSch();
        if (cfg.sshKey != null && !cfg.sshKey.trim().isEmpty()) {
            jsch.addIdentity("cdn", cfg.sshKey.getBytes("UTF-8"), null,
                    (cfg.sshPass == null ? "" : cfg.sshPass).getBytes("UTF-8"));
        }
        Session s = jsch.getSession(cfg.sshUser, cfg.sshHost, cfg.sshPort);
        Properties p = new Properties();
        p.put("StrictHostKeyChecking", "no");
        s.setConfig(p);
        if (cfg.sshKey != null && !cfg.sshKey.trim().isEmpty()) {
            s.setConfig("PreferredAuthentications", "publickey");
        } else {
            s.setPassword(cfg.sshPass);
            s.setConfig("PreferredAuthentications", "password,keyboard-interactive");
        }
        s.connect(15000);
        return s;
    }

    // ---- ssh exec helper ----
    private static class Exec { String out; int code; }

    private Exec exec(Session session, String cmd, byte[] stdin) throws Exception {
        ChannelExec ch = (ChannelExec) session.openChannel("exec");
        ch.setCommand(cmd);
        ch.setPty(false);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ch.setOutputStream(out);
        ch.setErrStream(out);
        OutputStream in = stdin != null ? ch.getOutputStream() : null;
        ch.connect(20000);
        if (stdin != null) {
            in.write(stdin); in.flush(); in.close();
        }
        long deadline = System.currentTimeMillis() + 120000;
        while (!ch.isClosed() && System.currentTimeMillis() < deadline) sleep(80);
        Exec e = new Exec();
        e.out = out.toString("UTF-8");
        e.code = ch.getExitStatus();
        ch.disconnect();
        return e;
    }

    private byte[] readAsset(String path) throws Exception {
        AssetManager am = ctx.getAssets();
        try (InputStream is = am.open(path)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(8 << 20);
            byte[] buf = new byte[65536];
            int n;
            while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    /** Перезапуск сервиса на VPS (после смены параметров). */
    public void restart(AdminCb cb2) {
        new Thread(() -> {
            Session s = null;
            try {
                s = connect();
                Exec e = exec(s, "systemctl restart " + SERVICE + " && systemctl is-active " + SERVICE, null);
                String out = e.out == null ? "" : e.out.trim();
                cb2.result(out.contains("active"), out);
            } catch (Throwable t) {
                cb2.result(false, "Ошибка: " + t.getMessage());
            } finally {
                if (s != null) s.disconnect();
            }
        }, "admin-restart").start();
    }

    private void fail(int idx, int total, String name, String detail) {
        cb.step(idx, total, name, "fail", detail);
        cb.done(false, name + " — ошибка: " + detail);
    }

    private static String trim(Exec e) {
        String s = (e.out == null ? "" : e.out.trim());
        return s.length() > 300 ? s.substring(0, 300) : s;
    }

    private static String tail(String s) {
        if (s == null) return "";
        String[] lines = s.trim().split("\n");
        int from = Math.max(0, lines.length - 6);
        StringBuilder b = new StringBuilder();
        for (int i = from; i < lines.length; i++) b.append(lines[i]).append('\n');
        return b.toString();
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }
}
