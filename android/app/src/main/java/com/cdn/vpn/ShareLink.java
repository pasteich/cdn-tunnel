package com.cdn.vpn;

import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Ссылка cdn://… — все настройки подключения одним значением, как vless://…
 *
 * Содержимое шифруется AES-256-GCM, поэтому в ссылке ничего не прочитать глазами
 * и обычный base64-декод ничего не даёт. Ключ общий для всех сборок (иначе друг
 * не расшифровал бы ссылку), так что это стойкая обфускация, а не тайна от того,
 * у кого есть APK: доступ к серверу по-прежнему решает пароль туннеля внутри.
 *
 * Формат совпадает с Go-частью (main.go, encodeShare/decodeShare):
 *   "cdn://" + base64url( [версия:1][nonce:12][шифртекст+тег] ),
 * ключ = SHA-256("cdn-tunnel/share/v1"), AAD = один байт версии.
 */
public final class ShareLink {

    public static final String SCHEME = "cdn://";
    private static final byte VERSION = 1;
    private static final String SECRET = "cdn-tunnel/share/v1";
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;

    private ShareLink() {}

    /** Ошибка разбора с текстом для пользователя. */
    public static class BadLink extends Exception {
        BadLink(String m) { super(m); }
    }

    /**
     * Собирает ссылку из готового удостоверения, выданного сервером
     * (ручка /admin/link/new). Только так ссылки и выпускаются: их реестр ведёт
     * сервер, поэтому владелец видит и может отозвать любую.
     */
    public static String encodeCred(String host, String ip, String cred, String label,
                                    int conns, boolean udp, String method, String transport) {
        try {
            JSONObject o = new JSONObject();
            o.put("ip", ip == null ? "" : ip);
            o.put("host", host == null ? "" : host);
            if (cred != null && !cred.isEmpty()) o.put("cred", cred);
            o.put("conns", conns);
            o.put("udp", udp);
            o.put("method", method);
            o.put("transport", transport);
            if (label != null && !label.isEmpty()) o.put("label", label);
            return seal(o.toString());
        } catch (Exception e) {
            return "";
        }
    }

    /** Удостоверение для уже выпущенной ссылки: подпись её id мастер-паролем. */
    public static String credFor(String master, String id) {
        try {
            return id + "." + credMac(master, id);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Собирает ссылку из настроек подключения. Мастер-пароль внутрь не кладём:
     * ссылка получает собственное удостоверение "<id>.<подпись>", выданное этим
     * паролем, — сервер проверит подпись и привяжет ссылку к первому устройству.
     */
    public static String encode(Config c, String label) {
        try {
            JSONObject o = new JSONObject();
            o.put("ip", c.ip == null ? "" : c.ip);
            o.put("host", c.host == null ? "" : c.host);
            String master = c.password == null ? "" : c.password;
            if (!master.isEmpty()) o.put("cred", issueCred(master));
            o.put("conns", c.conns);
            o.put("udp", c.udp);
            o.put("method", c.method);
            o.put("transport", c.transport);
            if (label != null && !label.isEmpty()) o.put("label", label);

            return seal(o.toString());
        } catch (Exception e) {
            return "";
        }
    }

    /** Шифрует полезную нагрузку и оформляет её в cdn://-ссылку. */
    private static String seal(String json) throws Exception {
        byte[] plain = json.getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(new byte[]{VERSION});
        byte[] sealed = cipher.doFinal(plain);

        byte[] out = new byte[1 + nonce.length + sealed.length];
        out[0] = VERSION;
        System.arraycopy(nonce, 0, out, 1, nonce.length);
        System.arraycopy(sealed, 0, out, 1 + nonce.length, sealed.length);
        return SCHEME + Base64.encodeToString(out, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    /** Разбирает ссылку и переносит настройки в cfg (имя клиента не трогает). */
    public static String decodeInto(String link, Config cfg) throws BadLink {
        if (link == null) throw new BadLink("пустая ссылка");
        String s = link.trim();
        int hash = s.indexOf('#');           // подпись после # — только для глаз
        if (hash >= 0) s = s.substring(0, hash);
        String low = s.toLowerCase();
        if (low.startsWith(SCHEME)) s = s.substring(SCHEME.length());
        else if (low.startsWith("cdn:")) s = s.substring(4);
        while (s.startsWith("/")) s = s.substring(1);
        s = s.trim();
        if (s.isEmpty()) throw new BadLink("в ссылке нет данных");

        byte[] raw;
        try {
            raw = Base64.decode(s, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        } catch (Exception e) {
            throw new BadLink("это не похоже на cdn://-ссылку");
        }
        if (raw.length < 1 + NONCE_LEN + 16) throw new BadLink("ссылка обрезана");
        if (raw[0] != VERSION) throw new BadLink("ссылка другой версии (" + raw[0] + ") — обновите приложение");

        byte[] plain;
        try {
            byte[] nonce = new byte[NONCE_LEN];
            System.arraycopy(raw, 1, nonce, 0, NONCE_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(new byte[]{VERSION});
            plain = cipher.doFinal(raw, 1 + NONCE_LEN, raw.length - 1 - NONCE_LEN);
        } catch (Exception e) {
            throw new BadLink("ссылка повреждена или не от этой программы");
        }

        try {
            JSONObject o = new JSONObject(new String(plain, StandardCharsets.UTF_8));
            String ip = o.optString("ip", "");
            String host = o.optString("host", "");
            if (ip.isEmpty() && host.isEmpty()) throw new BadLink("в ссылке нет адреса сервера");
            if (!ip.isEmpty()) cfg.ip = ip;
            cfg.host = host;
            // Ссылка нового образца несёт удостоверение, старая — сам пароль.
            cfg.cred = o.optString("cred", "");
            cfg.password = o.optString("pass", "");
            int conns = o.optInt("conns", cfg.conns);
            if (conns > 0) cfg.conns = conns;
            cfg.udp = o.optBoolean("udp", cfg.udp);
            String m = o.optString("method", "");
            if (!m.isEmpty()) cfg.method = "get".equalsIgnoreCase(m) ? "get" : "post";
            String tr = o.optString("transport", "");
            if (!tr.isEmpty()) cfg.transport = "stream".equalsIgnoreCase(tr) ? "stream" : "chunked";
            return o.optString("label", "");
        } catch (BadLink b) {
            throw b;
        } catch (Exception e) {
            throw new BadLink("содержимое ссылки не разобрано");
        }
    }

    /**
     * Выпускает удостоверение для новой ссылки: случайный id + подпись HMAC-SHA256
     * мастер-паролем. Формат совпадает с Go (issueCred/credMAC в ../main.go).
     */
    public static String issueCred(String master) {
        try {
            byte[] idb = new byte[8];
            new SecureRandom().nextBytes(idb);
            StringBuilder hex = new StringBuilder();
            for (byte b : idb) hex.append(String.format("%02x", b));
            String id = hex.toString();
            return id + "." + credMac(master, id);
        } catch (Exception e) {
            return "";
        }
    }

    private static String credMac(String master, String id) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(master.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] full = mac.doFinal(("cdn-tunnel/link/v1:" + id).getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 16; i++) out.append(String.format("%02x", full[i]));
        return out.toString();
    }

    private static SecretKeySpec key() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return new SecretKeySpec(md.digest(SECRET.getBytes(StandardCharsets.UTF_8)), "AES");
    }
}
