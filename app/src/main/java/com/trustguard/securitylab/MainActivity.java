package com.trustguard.securitylab;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;

public class MainActivity extends Activity {
    private static final int PICK_APK = 41;
    private TextView report;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);

        TextView title = new TextView(this);
        title.setText("TrustGuard Security Lab");
        title.setTextSize(23);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView intro = new TextView(this);
        intro.setText("تحلیل محلی و آفلاین فایل APK؛ هیچ فایلی ارسال نمی‌شود.");
        intro.setTextSize(16);
        intro.setPadding(0, 18, 0, 18);
        root.addView(intro);

        Button choose = new Button(this);
        choose.setText("انتخاب فایل APK");
        root.addView(choose);
        choose.setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("application/vnd.android.package-archive");
            startActivityForResult(intent, PICK_APK);
        });

        report = new TextView(this);
        report.setTextSize(14);
        report.setText("پس از انتخاب APK، گزارش اینجا نمایش داده می‌شود.");
        ScrollView scroll = new ScrollView(this);
        scroll.addView(report);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != PICK_APK || resultCode != RESULT_OK || data == null) return;
        Uri uri = data.getData();
        if (uri == null) return;
        try {
            getContentResolver().takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        } catch (Exception ignored) { }
        analyze(uri);
    }

    private void analyze(Uri uri) {
        File apk = new File(getCacheDir(), "selected-analysis.apk");
        try (InputStream in = getContentResolver().openInputStream(uri);
             java.io.FileOutputStream out = new java.io.FileOutputStream(apk)) {
            if (in == null) throw new IllegalStateException("فایل قابل خواندن نیست");
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) out.write(buffer, 0, n);

            PackageManager pm = getPackageManager();
            PackageInfo pi = pm.getPackageArchiveInfo(apk.getAbsolutePath(),
                    PackageManager.GET_ACTIVITIES | PackageManager.GET_SERVICES |
                    PackageManager.GET_RECEIVERS | PackageManager.GET_PROVIDERS |
                    PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES);
            if (pi == null || pi.applicationInfo == null) {
                report.setText("فایل انتخاب‌شده APK معتبر یا قابل‌شناسایی نیست.");
                return;
            }
            StringBuilder s = new StringBuilder();
            s.append("گزارش تحلیل APK\n\n");
            s.append("Package: ").append(pi.packageName).append('\n');
            s.append("Version: ").append(pi.versionName).append('\n');
            s.append("Version code: ").append(pi.versionCode).append('\n');
            s.append("Debuggable: ").append((pi.applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0).append("\n\n");

            s.append("Permissions:\n");
            if (pi.requestedPermissions == null || pi.requestedPermissions.length == 0) s.append("None declared\n");
            else for (String p : pi.requestedPermissions) s.append("• ").append(p).append('\n');

            s.append("\nExported activities:\n");
            if (pi.activities != null) for (android.content.pm.ActivityInfo c : pi.activities)
                if (c.exported) s.append("• ").append(c.name).append('\n');

            s.append("\nExported services:\n");
            if (pi.services != null) for (android.content.pm.ServiceInfo c : pi.services)
                if (c.exported) s.append("• ").append(c.name).append('\n');

            s.append("\nExported receivers:\n");
            if (pi.receivers != null) for (android.content.pm.ActivityInfo c : pi.receivers)
                if (c.exported) s.append("• ").append(c.name).append('\n');

            s.append("\nExported providers:\n");
            if (pi.providers != null) for (android.content.pm.ProviderInfo c : pi.providers)
                if (c.exported) s.append("• ").append(c.name).append('\n');

            s.append("\nAPK SHA-256:\n").append(sha256(apk)).append('\n');
            s.append("\nNote: exported components and permissions are indicators for manual review, not proof of a vulnerability.");
            report.setText(s.toString());
        } catch (Exception e) {
            report.setText("تحلیل انجام نشد: " + e.getClass().getSimpleName() + " — " + e.getMessage());
        } finally {
            // The temporary copy is removed after analysis.
            //noinspection ResultOfMethodCallIgnored
            apk.delete();
        }
    }

    private String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) digest.update(buffer, 0, n);
        }
        StringBuilder hex = new StringBuilder();
        for (byte b : digest.digest()) hex.append(String.format("%02x", b & 0xff));
        return hex.toString();
    }
}
