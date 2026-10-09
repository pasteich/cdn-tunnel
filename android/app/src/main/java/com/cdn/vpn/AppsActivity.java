package com.cdn.vpn;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;

import com.google.android.material.materialswitch.MaterialSwitch;
import com.google.android.material.textfield.TextInputEditText;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Выбор приложений для раздельной маршрутизации: список установленных
 * приложений с галочками, поиск по имени/пакету, фильтр системных.
 * Выбор сохраняется в Config сразу при клике.
 */
public class AppsActivity extends Activity {

    private ListView list;
    private AppsAdapter adapter;
    private TextInputEditText etSearch;
    private TextView tvSummary;
    private Config cfg;

    private static final int LOAD = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_apps);
        cfg = Config.load(this);

        list = findViewById(R.id.list_apps);
        etSearch = findViewById(R.id.et_search);
        tvSummary = findViewById(R.id.tv_apps_summary);
        adapter = new AppsAdapter();
        list.setAdapter(adapter);

        findViewById(R.id.btn_apps_back).setOnClickListener(v -> finish());
        findViewById(R.id.btn_apps_all).setOnClickListener(v -> setAll(true));
        findViewById(R.id.btn_apps_none).setOnClickListener(v -> setAll(false));

        MaterialSwitch swSystem = findViewById(R.id.sw_system);
        swSystem.setOnCheckedChangeListener((CompoundButton b, boolean on) -> {
            adapter.showSystem = on;
            adapter.refilter();
        });

        etSearch.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
            public void onTextChanged(CharSequence s, int a, int b, int c) {}
            public void afterTextChanged(Editable s) { adapter.getFilter().filter(s.toString()); }
        });

        // Список приложений грузится асинхронно: PackageManager на большом
        // телефоне может думать пару секунд, экран не должен виснуть.
        AsyncTask.SERIAL_EXECUTOR.execute(() -> {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> raw = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            List<AppRow> rows = new ArrayList<>();
            for (ApplicationInfo ai : raw) {
                if (packageName().equals(ai.packageName)) continue;
                AppRow r = new AppRow();
                r.pkg = ai.packageName;
                r.system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                r.label = String.valueOf(pm.getApplicationLabel(ai));
                Drawable ic = null;
                try { ic = pm.getApplicationIcon(ai); } catch (Throwable ignored) {}
                r.icon = ic;
                rows.add(r);
            }
            Collections.sort(rows, (a, b2) -> a.label.compareToIgnoreCase(b2.label));
            runOnUiThread(() -> adapter.setAll(rows));
        });
    }

    private String packageName() { return getPackageName(); }

    private void setAll(boolean on) {
        for (AppRow r : adapter.visible) {
            r.checked = on;
            if (on) cfg.apps.add(r.pkg); else cfg.apps.remove(r.pkg);
        }
        adapter.notifyDataSetChanged();
        persist();
    }

    private void persist() {
        cfg.appsMode = modeOf();
        cfg.save(this);
        tvSummary.setText(summary());
    }

    private String modeOf() {
        return getIntent() == null || getIntent().getStringExtra("mode") == null
                ? cfg.appsMode : getIntent().getStringExtra("mode");
    }

    private String summary() {
        int n = cfg.apps.size();
        boolean allow = "allow".equals(modeOf());
        if (n == 0) {
            return allow ? "Ничего не выбрано — в VPN не пойдёт ни одно приложение"
                         : "Ничего не выбрано — в VPN пойдут все приложения";
        }
        return (allow ? "Выбрано" : "Исключено") + ": " + n;
    }

    private class AppRow {
        String pkg, label;
        Drawable icon;
        boolean system, checked;
    }

    private class AppsAdapter extends BaseAdapter implements Filterable {
        final List<AppRow> all = new ArrayList<>();
        final List<AppRow> visible = new ArrayList<>();
        boolean showSystem = false;
        String query = "";

        void setAll(List<AppRow> rows) {
            all.clear();
            all.addAll(rows);
            refilter();
        }

        void refilter() {
            visible.clear();
            String q = query == null ? "" : query.toLowerCase();
            for (AppRow r : all) {
                if (!showSystem && r.system) continue;
                if (!q.isEmpty() && !r.label.toLowerCase().contains(q) && !r.pkg.toLowerCase().contains(q)) continue;
                r.checked = cfg.apps.contains(r.pkg);
                visible.add(r);
            }
            notifyDataSetChanged();
            int sys = 0;
            for (AppRow r : all) if (r.system) sys++;
            tvSummary.setText(summary() + (showSystem ? "" : " · системные скрыты (" + sys + ")"));
        }

        @Override public int getCount() { return visible.size(); }
        @Override public AppRow getItem(int i) { return visible.get(i); }
        @Override public long getItemId(int i) { return i; }

        @Override public View getView(int i, View convertView, ViewGroup parent) {
            View v = convertView;
            if (v == null) {
                v = LayoutInflater.from(AppsActivity.this).inflate(R.layout.item_app, parent, false);
            }
            final AppRow r = visible.get(i);
            ImageView icon = v.findViewById(R.id.app_icon);
            TextView label = v.findViewById(R.id.app_label);
            TextView pkg = v.findViewById(R.id.app_pkg);
            CheckBox cb = v.findViewById(R.id.app_check);
            icon.setImageDrawable(r.icon);
            label.setText(r.label);
            pkg.setText(r.pkg);
            cb.setOnCheckedChangeListener(null);
            cb.setChecked(r.checked);
            View.OnClickListener toggle = v2 -> {
                r.checked = !r.checked;
                cb.setChecked(r.checked);
                if (r.checked) cfg.apps.add(r.pkg); else cfg.apps.remove(r.pkg);
                persist();
            };
            v.setOnClickListener(toggle);
            cb.setOnClickListener(toggle);
            return v;
        }

        @Override public Filter getFilter() {
            return new Filter() {
                @Override protected Filter.FilterResults performFiltering(CharSequence constraint) {
                    query = constraint == null ? "" : constraint.toString();
                    Filter.FilterResults res = new Filter.FilterResults();
                    res.count = 1;
                    return res;
                }
                @Override protected void publishResults(CharSequence constraint, Filter.FilterResults results) { refilter(); }
            };
        }
    }
}
