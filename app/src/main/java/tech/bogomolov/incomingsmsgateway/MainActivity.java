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
        startServiceSafe();
    }

    /**
     * Keystore reads run off the main thread: key generation and decryption
     * can block for seconds on some devices, which looked like a freeze,
     * and any Keystore failure used to escape uncaught and close the app
     * instantly. Status computation now runs in the background and any
     * failure shows the OFF state instead of crashing.
     */
    private void refreshStatus() {
        final TextView status = findViewById(R.id.status_text);
        final TextView detail = findViewById(R.id.status_detail);
        if (status == null || detail == null) {
            return;
        }
        new Thread(() -> {
            final boolean smsGranted;
            final Set<String> allowlist;
            final String url;
            final int accepted;
            final String deviceId;
            try {
                smsGranted = ContextCompat.checkSelfPermission(
                        MainActivity.this, Manifest.permission.RECEIVE_SMS)
                        == PackageManager.PERMISSION_GRANTED;
                allowlist = SecureStore.getAllowlist(MainActivity.this);
                url = SecureStore.getWorkerUrl(MainActivity.this);
                accepted = SecureStore.getAcceptedCount(MainActivity.this);
                deviceId = SecureStore.getDeviceId(MainActivity.this);
            } catch (Exception e) {
                // Never crash the status screen on a storage/Keystore failure.
                String keyError = SecureStore.getLastKeystoreError();
                final String detailText = "Secure storage is unavailable on this device. "
                        + "Forwarding is OFF. "
                        + (keyError == null || keyError.isEmpty()
                                ? "Reopen the app; if this persists, clear the app's storage in Android Settings and try again."
                                : "Keystore error: " + keyError);
                runOnUiThread(() -> {
                    status.setText(R.string.status_off);
                    detail.setText(detailText);
                });
                return;
            }
            final boolean configured = smsGranted && url != null && !url.isEmpty()
                    && !allowlist.isEmpty() && MetaHttpClient.isValidConfiguredUrl(url);
            final String host = url == null ? "" : MetaHttpClient.describeHost(url);
            runOnUiThread(() -> {
                if (!smsGranted) {
                    status.setText(R.string.status_no_permission);
                } else if (configured) {
                    status.setText(R.string.status_on);
                } else {
                    status.setText(R.string.status_off);
                }
                detail.setText(getString(R.string.status_detail, allowlist.size(), host,
                        accepted, deviceId));
            });
        }).start();
    }

    private void startServiceSafe() {
        try {
            if (!isServiceRunning()) {
                startService();
            }
        } catch (Exception ignored) {
            // Foreground-service start can be refused by the system (e.g.
            // ForegroundServiceStartNotAllowedException). The SMS receiver
            // still works without the indicator service; never crash for it.
        }
    }

    private boolean isServiceRunning() {
        try {
            ActivityManager manager = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
            if (manager == null) {
                return false;
            }
            for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
                if (SmsReceiverService.class.getName().equals(service.service.getClassName())) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            return false;
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
