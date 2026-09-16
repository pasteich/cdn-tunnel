package com.cdn.vpn;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

/** Holds all tunnel + VPN settings and persists them in SharedPreferences. */
public class Config {
    // --- tunnel client (main.go -client) ---
    public String ip = "151.236.109.225";   // -ip   : IP CDN
    public String host = "u8t.fun";          // -host : Host/SNI
    public String password = "";             // -password
    public int port = 8090;                  // -listen 127.0.0.1:<port>
    public int conns = 8;                    // -conns
    public boolean udp = true;               // -udp
    public String method = "post";           // -method : post | get
    public String transport = "chunked";     // -transport : chunked | stream
    public boolean fastopen = true;          // -fastopen

    // --- VPN / tun2socks wrapper ---
    public String dns = "1.1.1.1";
    public int mtu = 1500;
    public boolean blockAAAA = true;
    public boolean debug = false;

    // --- деплой серверной части по SSH (вкладка «Сервер») ---
    public String sshHost = "";
    public int sshPort = 22;
    public String sshUser = "root";
    public String sshPass = "";
    public String sshKey = "";              // приватный ключ (PEM); если не пусто — вход по ключу
    public String serverAddr = ":80";       // -addr на сервере
    public String serverMethod = "both";    // -method на сервере (post|get|both)
    public int restartMin = 0;              // рестарт сервиса каждые N минут (0 = не рестартить)

    private static final String PREFS = "cdntunnel";

    public static Config load(Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        Config c = new Config();
        c.ip = p.getString("ip", c.ip);
        c.host = p.getString("host", c.host);
        c.password = p.getString("password", c.password);
        c.port = p.getInt("port", c.port);
        c.conns = p.getInt("conns", c.conns);
        c.udp = p.getBoolean("udp", c.udp);
        c.method = p.getString("method", c.method);
        c.transport = p.getString("transport", c.transport);
        c.fastopen = p.getBoolean("fastopen", c.fastopen);
        c.dns = p.getString("dns", c.dns);
        c.mtu = p.getInt("mtu", c.mtu);
        c.blockAAAA = p.getBoolean("blockAAAA", c.blockAAAA);
        c.debug = p.getBoolean("debug", c.debug);
        c.sshHost = p.getString("sshHost", c.sshHost);
        c.sshPort = p.getInt("sshPort", c.sshPort);
        c.sshUser = p.getString("sshUser", c.sshUser);
        c.sshPass = p.getString("sshPass", c.sshPass);
        c.sshKey = p.getString("sshKey", c.sshKey);
        c.serverAddr = p.getString("serverAddr", c.serverAddr);
        c.serverMethod = p.getString("serverMethod", c.serverMethod);
        c.restartMin = p.getInt("restartMin", c.restartMin);
        return c;
    }

    public void save(Context ctx) {
        SharedPreferences.Editor e = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit();
        e.putString("ip", ip);
        e.putString("host", host);
        e.putString("password", password);
        e.putInt("port", port);
        e.putInt("conns", conns);
        e.putBoolean("udp", udp);
        e.putString("method", method);
        e.putString("transport", transport);
        e.putBoolean("fastopen", fastopen);
        e.putString("dns", dns);
        e.putInt("mtu", mtu);
        e.putBoolean("blockAAAA", blockAAAA);
        e.putBoolean("debug", debug);
        e.putString("sshHost", sshHost);
        e.putInt("sshPort", sshPort);
        e.putString("sshUser", sshUser);
        e.putString("sshPass", sshPass);
        e.putString("sshKey", sshKey);
        e.putString("serverAddr", serverAddr);
        e.putString("serverMethod", serverMethod);
        e.putInt("restartMin", restartMin);
        e.apply();
    }

    public void toIntent(Intent i) {
        i.putExtra("ip", ip);
        i.putExtra("host", host);
        i.putExtra("password", password);
        i.putExtra("port", port);
        i.putExtra("conns", conns);
        i.putExtra("udp", udp);
        i.putExtra("method", method);
        i.putExtra("transport", transport);
        i.putExtra("fastopen", fastopen);
        i.putExtra("dns", dns);
        i.putExtra("mtu", mtu);
        i.putExtra("blockAAAA", blockAAAA);
        i.putExtra("debug", debug);
    }

    public static Config fromIntent(Intent i) {
        Config c = new Config();
        if (i.hasExtra("ip")) c.ip = i.getStringExtra("ip");
        if (i.hasExtra("host")) c.host = i.getStringExtra("host");
        if (i.hasExtra("password")) c.password = i.getStringExtra("password");
        c.port = i.getIntExtra("port", c.port);
        c.conns = i.getIntExtra("conns", c.conns);
        c.udp = i.getBooleanExtra("udp", c.udp);
        if (i.hasExtra("method")) c.method = i.getStringExtra("method");
        if (i.hasExtra("transport")) c.transport = i.getStringExtra("transport");
        c.fastopen = i.getBooleanExtra("fastopen", c.fastopen);
        if (i.hasExtra("dns")) c.dns = i.getStringExtra("dns");
        c.mtu = i.getIntExtra("mtu", c.mtu);
        c.blockAAAA = i.getBooleanExtra("blockAAAA", c.blockAAAA);
        c.debug = i.getBooleanExtra("debug", c.debug);
        return c;
    }
}
