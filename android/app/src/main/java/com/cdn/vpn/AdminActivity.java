package com.cdn.vpn;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.progressindicator.LinearProgressIndicator;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Панель управления сервером: открывается со вкладки «Сервер» после успешного
 * подключения по SSH и читает ручку /admin запущенного сервера (SSH → curl на
 * localhost, см. DeployManager.admin).
 *
 * Показывает всё, что знает сервер: аптайм и трафик сервера, каждую выпущенную
 * ссылку (использована или нет, к какому устройству привязана, сколько через неё
 * прошло) и каждого клиента с его трафиком. Отсюда же ссылки выпускаются,
 * отвязываются, отзываются и удаляются, а клиенты — отключаются и блокируются.
 */
public class AdminActivity extends AppCompatActivity {

    private Config cfg;
    private DeployManager dm;

    private TextView tvHost, tvOnline, tvSub, tvDown, tvUp, tvLinksCount, tvUsersCount, tvOutdated;
    private View boxOutdated;
    private LinearLayout boxLinks, boxUsers;
    private LinearProgressIndicator progress;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean busy = false;
    private final Runnable auto = new Runnable() {
        @Override public void run() {
            refresh(false);
            ui.postDelayed(this, 5000);
        }
    };

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_admin);
        cfg = Config.load(this);
        dm = new DeployManager(this, cfg, NOOP);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Управление сервером");
        }

        tvHost = findViewById(R.id.tv_adm_host);
        tvOnline = findViewById(R.id.tv_adm_online);
        tvSub = findViewById(R.id.tv_adm_sub);
        tvDown = findViewById(R.id.tv_adm_down);
        tvUp = findViewById(R.id.tv_adm_up);
        tvLinksCount = findViewById(R.id.tv_adm_links_count);
        tvUsersCount = findViewById(R.id.tv_adm_users_count);
        boxLinks = findViewById(R.id.box_links);
        boxUsers = findViewById(R.id.box_admin_users);
        progress = findViewById(R.id.adm_progress);
        boxOutdated = findViewById(R.id.box_outdated);
        tvOutdated = findViewById(R.id.tv_outdated);
        ((MaterialButton) findViewById(R.id.btn_adm_update)).setOnClickListener(v -> updateServer());

        tvHost.setText(cfg.sshHost == null || cfg.sshHost.isEmpty() ? "сервер" : cfg.sshHost);

        ((MaterialButton) findViewById(R.id.btn_new_link)).setOnClickListener(v -> newLink());
        ((MaterialButton) findViewById(R.id.btn_adm_refresh)).setOnClickListener(v -> refresh(true));
        ((MaterialButton) findViewById(R.id.btn_adm_limit)).setOnClickListener(v -> askLimit());
        ((MaterialButton) findViewById(R.id.btn_adm_restart)).setOnClickListener(v -> restart());
    }

    @Override public boolean onSupportNavigateUp() { finish(); return true; }

    @Override protected void onResume() { super.onResume(); ui.post(auto); }
    @Override protected void onPause()  { super.onPause(); ui.removeCallbacks(auto); }

    // ---------- загрузка и отрисовка ----------

    private void refresh(boolean loud) {
        if (busy) return;
        busy = true;
        if (loud) progress.setVisibility(View.VISIBLE);
        dm.admin("/admin", (ok, body) -> ui.post(() -> {
            busy = false;
            progress.setVisibility(View.GONE);
            if (!ok) {
                tvSub.setText("✗ " + hint(body));
                return;
            }
            try {
                render(new JSONObject(body));
                if (loud) toast("Обновлено");
            } catch (Exception e) {
                tvSub.setText("✗ ответ сервера не разобран");
            }
        }));
    }

    /** Версия серверной части, которую ждёт это приложение (см. serverVersion в main.go). */
    private static final String NEEDED_VERSION = "1.4";

    private void render(JSONObject d) {
        String version = d.optString("version", "?");
        boolean old = !NEEDED_VERSION.equals(version);
        boxOutdated.setVisibility(old ? View.VISIBLE : View.GONE);
        if (old) {
            tvOutdated.setText("На сервере сборка " + version + ", приложению нужна " + NEEDED_VERSION
                    + ". Часть кнопок (в том числе выпуск ссылок) вернёт «unknown action», пока сервер не обновлён.");
        }
        int limit = d.optInt("limit", 0);
        int online = d.optInt("online", 0);
        tvOnline.setText(limit > 0 ? online + "/" + limit + " онлайн" : online + " онлайн");
        tvSub.setText("версия " + d.optString("version", "?")
                + " · аптайм " + dur(d.optLong("uptime", 0))
                + " · стримов " + d.optInt("streams", 0) + " · udp " + d.optInt("udp", 0)
                + "\nлимит " + (limit > 0 ? String.valueOf(limit) : "не задан")
                + " · метод " + d.optString("method", "?")
                + " · пароль " + (d.optBoolean("password", false) ? "есть" : "нет"));
        tvDown.setText(human(d.optLong("down", 0)));
        tvUp.setText(human(d.optLong("up", 0)));

        JSONArray links = d.optJSONArray("links");
        boxLinks.removeAllViews();
        int alive = 0, bound = 0;
        if (links == null || links.length() == 0) {
            boxLinks.addView(empty("Ссылок пока нет. «Новая ссылка» — и отправьте её другу."));
        } else {
            for (int i = 0; i < links.length(); i++) {
                JSONObject l = links.optJSONObject(i);
                if (l == null) continue;
                if (!l.optBoolean("revoked", false)) alive++;
                if (!l.optString("device", "").isEmpty()) bound++;
                boxLinks.addView(linkCard(l));
            }
        }
        tvLinksCount.setText(alive + " активн. · " + bound + " привязано");

        JSONArray users = d.optJSONArray("users");
        boxUsers.removeAllViews();
        if (users == null || users.length() == 0) {
            boxUsers.addView(empty("Клиентов ещё не было."));
            tvUsersCount.setText("");
        } else {
            long totalUp = 0, totalDown = 0;
            for (int i = 0; i < users.length(); i++) {
                JSONObject u = users.optJSONObject(i);
                if (u == null) continue;
                totalUp += u.optLong("up", 0);
                totalDown += u.optLong("down", 0);
                boxUsers.addView(userCard(u));
            }
            tvUsersCount.setText("всего ↓ " + human(totalDown) + " ↑ " + human(totalUp));
        }
    }

    private View linkCard(JSONObject l) {
        View v = LayoutInflater.from(this).inflate(R.layout.item_link, boxLinks, false);
        final String id = l.optString("id", "");
        final String label = l.optString("label", "");
        final String device = l.optString("device", "");
        final boolean revoked = l.optBoolean("revoked", false);
        final String name = l.optString("name", "");

        TextView title = v.findViewById(R.id.tv_link_title);
        TextView state = v.findViewById(R.id.tv_link_state);
        title.setText(label.isEmpty() ? "Без подписи" : label);
        if (revoked) {
            state.setText("отозвана"); state.setTextColor(0xFFD0674A);
        } else if (device.isEmpty()) {
            state.setText("не использована"); state.setTextColor(0xFFC7A34E);
        } else {
            state.setText("привязана"); state.setTextColor(0xFF9FB86A);
        }

        String meta = "id " + id + " · создана " + agoPhrase(l.optLong("created", 0));
        if (!device.isEmpty()) {
            meta += "\nустройство " + device + (name.isEmpty() ? "" : " · клиент «" + name + "»")
                    + "\nпоследний раз " + agoPhrase(l.optLong("last_use", 0));
        }
        ((TextView) v.findViewById(R.id.tv_link_meta)).setText(meta);
        ((TextView) v.findViewById(R.id.tv_link_traffic)).setText(
                "↓ " + human(l.optLong("down", 0)) + "   ↑ " + human(l.optLong("up", 0)));

        MaterialButton share = v.findViewById(R.id.btn_link_share);
        MaterialButton unbind = v.findViewById(R.id.btn_link_unbind);
        MaterialButton revoke = v.findViewById(R.id.btn_link_revoke);
        MaterialButton del = v.findViewById(R.id.btn_link_delete);

        // Ссылку можно собрать заново из её id: удостоверение — подпись мастер-паролем.
        share.setOnClickListener(x -> shareExisting(id, label));
        share.setEnabled(!revoked);
        unbind.setEnabled(!device.isEmpty());
        unbind.setOnClickListener(x -> act("/admin/link/unbind?id=" + id, "Ссылка отвязана"));
        revoke.setText(revoked ? "Вернуть" : "Отозвать");
        revoke.setOnClickListener(x -> {
            if (revoked) act("/admin/link/restore?id=" + id, "Ссылка снова активна");
            else confirm("Отозвать ссылку?", "Клиент по ней больше не подключится. Счётчики останутся.",
                    () -> act("/admin/link/revoke?id=" + id, "Ссылка отозвана"));
        });
        del.setOnClickListener(x -> confirm("Удалить ссылку?",
                "Пропадёт из списка вместе со счётчиками трафика.",
                () -> act("/admin/link/delete?id=" + id, "Ссылка удалена")));
        return v;
    }

    private View userCard(JSONObject u) {
        View v = LayoutInflater.from(this).inflate(R.layout.item_user, boxUsers, false);
        final String name = u.optString("name", "?");
        final boolean online = u.optBoolean("online", false);
        final boolean banned = u.optBoolean("banned", false);

        TextView dot = v.findViewById(R.id.tv_user_dot);
        dot.setTextColor(banned ? 0xFFD0674A : online ? 0xFF9FB86A : 0xFF6B5B49);
        ((TextView) v.findViewById(R.id.tv_user_name)).setText(name);
        TextView state = v.findViewById(R.id.tv_user_state);
        state.setText(banned ? "бан" : online ? "онлайн" : "офлайн");
        state.setTextColor(banned ? 0xFFD0674A : online ? 0xFF9FB86A : 0xFF8A7A66);

        ((TextView) v.findViewById(R.id.tv_user_traffic)).setText(
                "↓ " + human(u.optLong("down", 0)) + "   ↑ " + human(u.optLong("up", 0)));

        StringBuilder meta = new StringBuilder("подключений: ").append(u.optLong("seen", 0));
        String ip = u.optString("ip", "");
        if (online) {
            if (!ip.isEmpty()) meta.append(" · ").append(ip);
            long since = u.optLong("since", 0);
            if (since > 0) meta.append(" · на связи ").append(dur(Math.max(0,
                    System.currentTimeMillis() / 1000 - since)));
        } else {
            meta.append(" · был ").append(agoPhrase(u.optLong("last", 0)));
        }
        String link = u.optString("link", "");
        if (!link.isEmpty()) meta.append("\nссылка ").append(link);
        ((TextView) v.findViewById(R.id.tv_user_meta)).setText(meta.toString());

        MaterialButton kick = v.findViewById(R.id.btn_user_kick);
        MaterialButton ban = v.findViewById(R.id.btn_user_ban);
        MaterialButton forget = v.findViewById(R.id.btn_user_forget);
        kick.setEnabled(online);
        kick.setOnClickListener(x -> act("/admin/kick?name=" + enc(name), "«" + name + "» отключён"));
        ban.setText(banned ? "Разбан" : "Бан");
        ban.setOnClickListener(x -> act("/admin/" + (banned ? "unban" : "ban") + "?name=" + enc(name),
                banned ? "Разблокирован" : "Заблокирован"));
        forget.setOnClickListener(x -> confirm("Забыть «" + name + "»?",
                "Клиент пропадёт из списка вместе со своими счётчиками.",
                () -> act("/admin/forget?name=" + enc(name), "Забыт")));
        return v;
    }

    // ---------- действия ----------

    private void act(String path, final String okMsg) {
        progress.setVisibility(View.VISIBLE);
        dm.admin(path, (ok, body) -> ui.post(() -> {
            progress.setVisibility(View.GONE);
            toast(ok ? okMsg : why(body));
            refresh(false);
        }));
    }

    /** Человеческое объяснение вместо сырого ответа сервера. */
    private static String why(String body) {
        String b = body == null ? "" : body;
        if (b.contains("unknown action")) return "На сервере старая сборка — нажмите «Обновить сервер»";
        if (b.contains("forbidden")) return "Сервер не принял мастер-ключ (вкладка «Сервер»)";
        return "Не вышло: " + hint(b);
    }

    /**
     * Выпускает ссылку на сервере (она сразу появляется в списке) и отдаёт её
     * в мессенджер. Host/SNI и IP CDN вводятся здесь же — приложение ничего
     * такого «из коробки» не знает.
     */
    private void newLink() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(8), dp(20), 0);
        final EditText host = field("Host / SNI (домен CDN)", cfg.linkHost);
        final EditText ip = field("IP CDN", cfg.linkIp);
        final EditText label = field("Кому (подпись ссылки)", "");
        box.addView(host); box.addView(ip); box.addView(label);

        new AlertDialog.Builder(this)
                .setTitle("Новая ссылка")
                .setView(box)
                .setPositiveButton("Выпустить", (d, w) -> {
                    final String h = host.getText().toString().trim();
                    final String i = ip.getText().toString().trim();
                    final String lb = label.getText().toString().trim();
                    if (h.isEmpty() || i.isEmpty()) { toast("Нужны и Host, и IP"); return; }
                    cfg.linkHost = h; cfg.linkIp = i; cfg.save(this);
                    progress.setVisibility(View.VISIBLE);
                    dm.admin("/admin/link/new?label=" + enc(lb), (ok, body) -> ui.post(() -> {
                        progress.setVisibility(View.GONE);
                        if (!ok) { toast(why(body)); return; }
                        try {
                            JSONObject o = new JSONObject(body);
                            String url = ShareLink.encodeCred(h, i, o.optString("cred", ""), lb,
                                    cfg.conns, cfg.udp, methodForLink(), cfg.transport);
                            if (url.isEmpty()) { toast("Не удалось собрать ссылку"); return; }
                            showLink(url, lb);
                            refresh(false);
                        } catch (Exception e) {
                            toast("Ответ сервера не разобран");
                        }
                    }));
                })
                .setNegativeButton("Отмена", null)
                .show();
    }

    /** Пересобирает ссылку по её id (удостоверение = подпись мастер-паролем). */
    private void shareExisting(String id, String label) {
        String master = master();
        if (master.isEmpty()) { toast("Не задан мастер-ключ сервера (вкладка «Сервер»)"); return; }
        if (cfg.linkHost.isEmpty() || cfg.linkIp.isEmpty()) {
            toast("Сначала выпустите новую ссылку — там задаются Host и IP");
            return;
        }
        String cred = ShareLink.credFor(master, id);
        String url = ShareLink.encodeCred(cfg.linkHost, cfg.linkIp, cred, label,
                cfg.conns, cfg.udp, methodForLink(), cfg.transport);
        if (url.isEmpty()) { toast("Не удалось собрать ссылку"); return; }
        showLink(url, label);
    }

    private void showLink(final String url, String label) {
        new AlertDialog.Builder(this)
                .setTitle(label == null || label.isEmpty() ? "Ссылка" : "Ссылка: " + label)
                .setMessage(url + "\n\nПривяжется к первому устройству, которое по ней подключится. "
                        + "Отозвать или отвязать можно здесь же.")
                .setPositiveButton("Отправить", (d, w) -> startActivity(Intent.createChooser(
                        new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, url),
                        "Отправить ссылку")))
                .setNeutralButton("Скопировать", (d, w) -> {
                    ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("cdn-tunnel", url));
                    toast("Скопировано");
                })
                .setNegativeButton("Закрыть", null)
                .show();
    }

    private void askLimit() {
        final EditText in = new EditText(this);
        in.setInputType(InputType.TYPE_CLASS_NUMBER);
        in.setHint("0 — без лимита");
        LinearLayout box = new LinearLayout(this);
        box.setPadding(dp(20), dp(8), dp(20), 0);
        box.addView(in);
        new AlertDialog.Builder(this)
                .setTitle("Лимит одновременных клиентов")
                .setMessage("Применяется сразу, без перезапуска сервера.")
                .setView(box)
                .setPositiveButton("Применить", (d, w) -> {
                    String v = in.getText().toString().trim();
                    if (v.isEmpty()) return;
                    act("/admin/limit?n=" + v, "Лимит: " + v);
                    try {
                        cfg.serverUsers = Integer.parseInt(v);
                        cfg.save(this); // чтобы следующий деплой не вернул старое значение
                    } catch (NumberFormatException ignored) {}
                })
                .setNegativeButton("Отмена", null)
                .show();
    }

    /** Заливает на VPS свежий бинарь из этого APK и перезапускает сервис. */
    private void updateServer() {
        confirm("Обновить сервер?", "Зальёт свежий бинарь из приложения и перезапустит сервис. "
                + "Клиенты переподключатся за несколько секунд.", () -> {
            progress.setVisibility(View.VISIBLE);
            tvSub.setText("Обновление сервера…");
            new DeployManager(this, cfg, new DeployManager.Cb() {
                public void step(int idx, int total, String name, String state, String detail) {
                    ui.post(() -> tvSub.setText("[" + (idx + 1) + "/" + total + "] " + name
                            + (detail == null || detail.isEmpty() ? "" : " — " + detail)));
                }
                public void done(boolean ok, String summary) {
                    ui.post(() -> {
                        progress.setVisibility(View.GONE);
                        toast(ok ? "Сервер обновлён" : "Не вышло: " + hint(summary));
                        refresh(false);
                    });
                }
            }).start();
        });
    }

    private void restart() {
        confirm("Перезапустить сервер?", "Клиенты переподключатся за несколько секунд.", () -> {
            progress.setVisibility(View.VISIBLE);
            dm.restart((ok, body) -> ui.post(() -> {
                progress.setVisibility(View.GONE);
                toast(ok ? "Сервис снова активен" : "Не вышло: " + hint(body));
                refresh(false);
            }));
        });
    }

    private void confirm(String title, String msg, Runnable go) {
        new AlertDialog.Builder(this).setTitle(title).setMessage(msg)
                .setPositiveButton("Да", (d, w) -> go.run())
                .setNegativeButton("Отмена", null).show();
    }

    // ---------- мелочи ----------

    /** Мастер-ключ сервера: подписывает ссылки и открывает админку. */
    private String master() {
        return cfg.serverPassword == null ? "" : cfg.serverPassword;
    }

    private String methodForLink() {
        // Сервер с -method both принимает оба; клиенту оставляем post.
        return "get".equalsIgnoreCase(cfg.serverMethod) ? "get" : "post";
    }

    private TextView empty(String text) {
        TextView v = new TextView(this);
        v.setText(text);
        v.setTextSize(12);
        v.setTextColor(0xFFB9A588);
        v.setPadding(dp(2), dp(4), 0, dp(8));
        return v;
    }

    private EditText field(String hint, String value) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true);
        e.setTextSize(15);
        if (value != null) e.setText(value);
        return e;
    }

    private static final DeployManager.Cb NOOP = new DeployManager.Cb() {
        public void step(int i, int t, String n, String s, String d) {}
        public void done(boolean ok, String s) {}
    };

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_SHORT).show(); }

    private static String enc(String s) {
        try { return java.net.URLEncoder.encode(s == null ? "" : s, "UTF-8"); }
        catch (Exception e) { return ""; }
    }

    /** Короткий и понятный хвост ошибки вместо простыни вывода. */
    private static String hint(String s) {
        if (s == null || s.trim().isEmpty()) return "сервер не ответил (запущен ли он?)";
        String t = s.trim().replaceAll("\\s+", " ");
        return t.length() > 140 ? t.substring(0, 140) + "…" : t;
    }

    private static String human(double b) {
        if (b >= 1e9) return String.format("%.2f GB", b / 1e9);
        if (b >= 1e6) return String.format("%.1f MB", b / 1e6);
        if (b >= 1e3) return String.format("%.0f KB", b / 1e3);
        return String.format("%.0f B", b);
    }

    private static String dur(long sec) {
        if (sec < 60) return sec + " с";
        if (sec < 3600) return (sec / 60) + " мин";
        if (sec < 86400) return (sec / 3600) + " ч " + ((sec % 3600) / 60) + " мин";
        return (sec / 86400) + " дн " + ((sec % 86400) / 3600) + " ч";
    }

    /** «только что» / «5 мин назад» — без корявого «только что назад». */
    private static String agoPhrase(long tSec) {
        String a = ago(tSec);
        return a.equals("только что") || a.equals("?") ? a : a + " назад";
    }

    private static String ago(long tSec) {
        if (tSec <= 0) return "?";
        long d = System.currentTimeMillis() / 1000 - tSec;
        if (d < 60) return "только что";
        if (d < 3600) return (d / 60) + " мин";
        if (d < 86400) return (d / 3600) + " ч";
        return (d / 86400) + " дн";
    }

    private int dp(int v) { return Math.round(getResources().getDisplayMetrics().density * v); }
}
