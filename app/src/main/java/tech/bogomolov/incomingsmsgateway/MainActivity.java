package tech.bogomolov.incomingsmsgateway;

import android.Manifest;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.ArrayList;
import java.util.Set;

/**
 * Status screen only. No message list, no failed-message list, no log viewer:
 * showing SMS contents or senders on screen would defeat the Meta-only,
 * no-history design. Only counts and configuration state are shown.
 */
public class MainActivity extends AppCompatActivity {

    private static final int PERMISSION_CODE = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ArrayList<String> permissions = new ArrayList<>();
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
                != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.RECEIVE_SMS);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS);
        }

        if (permissions.isEmpty()) {
            showStatus();
        } else {
            ActivityCompat.requestPermissions(this, permissions.toArray(new String[0]), PERMISSION_CODE);
        }

        Button settingsButton = findViewById(R.id.btn_settings);
        settingsButton.setOnClickListener(v ->
                startActivity(new Intent(this, SettingsActivity.class)));
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_CODE
                && ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
                == PackageManager.PERMISSION_GRANTED) {
            showStatus();
        } else {
            showStatus();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();
    }

    private void showStatus() {
        refreshStatus();
        if (!isServiceRunning()) {
            startService();
        }
    }

    private void refreshStatus() {
        TextView status = findViewById(R.id.status_text);
        TextView detail = findViewById(R.id.status_detail);
        if (status == null || detail == null) {
            return;
        }
        boolean smsGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
                == PackageManager.PERMISSION_GRANTED;
        Set<String> allowlist = SecureStore.getAllowlist(this);
        String url = SecureStore.getWorkerUrl(this);
        boolean configured = smsGranted && url != null && !url.isEmpty() && !allowlist.isEmpty()
                && MetaHttpClient.isValidConfiguredUrl(url);
        if (!smsGranted) {
            status.setText(R.string.status_no_permission);
        } else if (configured) {
            status.setText(R.string.status_on);
        } else {
            status.setText(R.string.status_off);
        }
        String host = url == null ? "" : MetaHttpClient.describeHost(url);
        detail.setText(getString(R.string.status_detail, allowlist.size(), host,
                SecureStore.getAcceptedCount(this), SecureStore.getDeviceId(this)));
    }

    private boolean isServiceRunning() {
        ActivityManager manager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (SmsReceiverService.class.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

    private void startService() {
        Context appContext = getApplicationContext();
        Intent intent = new Intent(this, SmsReceiverService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent);
        } else {
            appContext.startService(intent);
        }
    }
}
