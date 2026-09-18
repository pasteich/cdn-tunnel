package com.cdn.vpn;

import android.os.Handler;
import android.os.Looper;

import java.util.ArrayList;
import java.util.List;

/**
 * Process-wide state bus shared between the VpnService and the UI. Both live in
 * the same process, so a static holder with a main-thread callback is enough.
 */
public final class TunState {

    // Connection phases (authoritative status, verified by an end-to-end probe).
    public static final String DISCONNECTED = "disconnected";
    public static final String STARTING     = "starting";
    public static final String CONNECTING   = "connecting";
    public static final String CONNECTED    = "connected";   // probe succeeded
    public static final String NO_ROUTE     = "noroute";     // up but traffic doesn't pass
    public static final String AUTH_FAIL    = "authfail";    // server rejected password
    public static final String USER_LIMIT   = "userlimit";   // server is full (-users)
    public static final String LINK_USED    = "linkused";    // link already bound to another device
    public static final String LINK_REVOKED = "linkrevoked"; // owner revoked this link
    public static final String BANNED       = "banned";      // owner blocked this client
    public static final String ERROR        = "error";

    /** Live traffic snapshot parsed from the tunnel's STATS output. */
    public static final class Stats {
        public long down, up, udpDown, udpUp;
        public long downRate, upRate;
        public long conns, total;
        public long rtt;
        /** Лимит -users на сервере: сколько клиентов сейчас подключено из скольких. */
        public long users, maxUsers;
    }

    /** Один клиент сервера: имя + онлайн он сейчас или нет. */
    public static final class User {
        public String name = "";
        public boolean online;
        public long last;   // когда видели последний раз, unix-секунды
        public long since;  // онлайн с какого времени, unix-секунды
        public long seen;   // сколько раз подключался
    }

    /** Список пользователей сервера (ответ /users, приходит строкой ROSTER). */
    public static final class Roster {
        public int limit;   // 0 — без лимита
        public int online;
        public final List<User> users = new ArrayList<>();
        public long at;     // когда получен, System.currentTimeMillis()
    }

    public interface Listener {
        void onRunningChanged(boolean running);
        void onLog(String line);
        void onPhase(String phase, String detail);
        void onStats(Stats s);
        void onRoster(Roster r);
    }

    private static final int MAX_LINES = 800;
    private static final Object LOCK = new Object();
    private static final List<String> LOG = new ArrayList<>();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private static volatile boolean running = false;
    private static volatile String phase = DISCONNECTED;
    private static volatile String phaseDetail = "";
    private static volatile Stats stats = new Stats();
    private static volatile Roster roster = null;
    private static volatile Listener listener;

    private TunState() {}

    public static boolean isRunning() { return running; }
    public static String phase() { return phase; }
    public static String phaseDetail() { return phaseDetail; }
    public static Stats stats() { return stats; }
    public static Roster roster() { return roster; }

    public static void setListener(Listener l) { listener = l; }

    public static List<String> snapshot() {
        synchronized (LOCK) { return new ArrayList<>(LOG); }
    }

    public static void setRunning(final boolean r) {
        running = r;
        final Listener l = listener;
        if (l != null) MAIN.post(() -> l.onRunningChanged(r));
    }

    public static void setPhase(final String p, final String detail) {
        phase = p;
        phaseDetail = detail == null ? "" : detail;
        final Listener l = listener;
        if (l != null) MAIN.post(() -> l.onPhase(p, phaseDetail));
    }

    public static void setStats(final Stats s) {
        stats = s;
        final Listener l = listener;
        if (l != null) MAIN.post(() -> l.onStats(s));
    }

    /**
     * Живой счётчик пользователей сервера (-users): обновляем сразу по строке
     * USERS, не дожидаясь очередного STATS, сохраняя остальные счётчики.
     */
    public static void setUsers(long now, long max) {
        Stats s = stats;
        Stats c = new Stats();
        c.down = s.down; c.up = s.up; c.udpDown = s.udpDown; c.udpUp = s.udpUp;
        c.downRate = s.downRate; c.upRate = s.upRate;
        c.conns = s.conns; c.total = s.total; c.rtt = s.rtt;
        c.users = now; c.maxUsers = max;
        setStats(c);
    }

    /** Новый список пользователей с сервера. */
    public static void setRoster(final Roster r) {
        roster = r;
        final Listener l = listener;
        if (l != null) MAIN.post(() -> l.onRoster(r));
    }

    public static void log(String line) {
        if (line == null) return;
        synchronized (LOCK) {
            LOG.add(line);
            while (LOG.size() > MAX_LINES) LOG.remove(0);
        }
        final Listener l = listener;
        if (l != null) MAIN.post(() -> l.onLog(line));
    }

    public static void clear() {
        synchronized (LOCK) { LOG.clear(); }
    }
}
