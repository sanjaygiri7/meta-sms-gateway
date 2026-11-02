package tech.bogomolov.incomingsmsgateway;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The only configuration screen.
 *
 * <p>Fields: Worker URL, exact sender allowlist (one per line, starts empty),
 * device ID (read-only, generated), HMAC secret provisioning (hidden until
 * the user explicitly taps Show, never logged, to be entered in the user's
 * own terminal with {@code wrangler secret put}, never in a chat).
 *
 * <p>Local-only sender identification: while the allowlist is empty, sender
 * IDs seen on this phone are listed here, sender only, with no message body
 * and no upload. Tapping one adds it to the allowlist field for the user to
 * save manually. Nothing is trusted automatically.
 *
 * <p>There is no heartbeat, no test request, and no backup export/import:
 * exporting the configuration would export the HMAC secret in plaintext.
 */
public class SettingsActivity extends AppCompatActivity {

    private EditText urlInput;
    private EditText allowlistInput;
    private TextView deviceIdView;
    private TextView secretView;
    private LinearLayout observedContainer;
    private TextView observedHint;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }

        urlInput = findViewById(R.id.input_worker_url);
        allowlistInput = findViewById(R.id.input_allowlist);
        deviceIdView = findViewById(R.id.text_device_id);
        secretView = findViewById(R.id.text_hmac_secret);
        observedContainer = findViewById(R.id.observed_container);
        observedHint = findViewById(R.id.observed_hint);

        String url = null;
        Set<String> allowlist = new LinkedHashSet<>();
        String deviceId = "";
        try {
            url = SecureStore.getWorkerUrl(this);
            allowlist = SecureStore.getAllowlist(this);
            deviceId = SecureStore.getDeviceId(this);
        } catch (Exception e) {
            // Secure storage unavailable: show empty fields instead of
            // closing instantly. Saving will surface the same failure.
            String keyError = SecureStore.getLastKeystoreError();
            Toast.makeText(this,
                    keyError == null || keyError.isEmpty()
                            ? "Secure storage is unavailable on this device."
                            : "Secure storage unavailable: " + keyError,
                    Toast.LENGTH_LONG).show();
        }
        if (url != null) {
            urlInput.setText(url);
        }
        if (!allowlist.isEmpty()) {
            allowlistInput.setText(TextUtils.join("\n", allowlist));
        }
        deviceIdView.setText(deviceId);
        secretView.setText(R.string.secret_hidden);

        findViewById(R.id.btn_copy_device_id).setOnClickListener(v -> {
            try {
                copyText(SecureStore.getDeviceId(this), R.string.copied_device_id);
            } catch (Exception e) {
                Toast.makeText(this, "Secure storage is unavailable on this device.",
                        Toast.LENGTH_LONG).show();
            }
        });

        Button showSecret = findViewById(R.id.btn_show_secret);
        showSecret.setOnClickListener(v -> showSecretWarning());

        Button copySecret = findViewById(R.id.btn_copy_secret);
        copySecret.setOnClickListener(v -> {
            // Only copy after the secret has been explicitly revealed in this session.
            if (secretView.getTag() == null) {
                Toast.makeText(this, R.string.secret_show_first, Toast.LENGTH_SHORT).show();
                return;
            }
            try {
                copyText(SecureStore.getHmacSecretBase64(this), R.string.copied_secret);
            } catch (Exception e) {
                Toast.makeText(this, "Secure storage is unavailable on this device.",
                        Toast.LENGTH_LONG).show();
            }
        });

        Button regenerate = findViewById(R.id.btn_regenerate_secret);
        regenerate.setOnClickListener(v -> confirmRegenerate());

        Button save = findViewById(R.id.btn_save_settings);
        save.setOnClickListener(v -> saveSettings());

        refreshObserved();
    }

    @Override
    public boolean onOptionsItemSelected(android.view.MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void showSecretWarning() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.secret_warning_title)
                .setMessage(R.string.secret_warning_message)
                .setPositiveButton(R.string.btn_show, (dialog, which) -> {
                    try {
                        secretView.setText(SecureStore.getHmacSecretBase64(this));
                        secretView.setTag(Boolean.TRUE);
                    } catch (Exception e) {
                        Toast.makeText(this, "Secure storage is unavailable on this device.",
                                Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    private void confirmRegenerate() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.regenerate_title)
                .setMessage(R.string.regenerate_message)
                .setPositiveButton(R.string.btn_regenerate, (dialog, which) -> {
                    try {
                        SecureStore.regenerateHmacSecret(this);
                    } catch (Exception e) {
                        Toast.makeText(this, "Secure storage is unavailable on this device.",
                                Toast.LENGTH_LONG).show();
                        return;
                    }
                    secretView.setText(R.string.secret_hidden);
                    secretView.setTag(null);
                    Toast.makeText(this, R.string.regenerated_toast, Toast.LENGTH_LONG).show();
                })
                .setNegativeButton(R.string.btn_cancel, null)
                .show();
    }

    private void copyText(String text, int toastRes) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("meta-sms-gateway", text));
        Toast.makeText(this, toastRes, Toast.LENGTH_SHORT).show();
    }

    private void refreshObserved() {
        List<String> observed;
        boolean allowlistEmpty;
        try {
            observed = SecureStore.getObservedSenders(this);
            allowlistEmpty = SecureStore.getAllowlist(this).isEmpty();
        } catch (Exception e) {
            observedHint.setVisibility(View.GONE);
            observedContainer.setVisibility(View.GONE);
            return;
        }
        observedContainer.removeAllViews();
        if (!allowlistEmpty || observed.isEmpty()) {
            observedHint.setVisibility(View.GONE);
            observedContainer.setVisibility(View.GONE);
            return;
        }
        observedHint.setVisibility(View.VISIBLE);
        observedContainer.setVisibility(View.VISIBLE);
        for (String sender : observed) {
            Button add = new Button(this);
            add.setText(getString(R.string.add_sender_button, sender));
            add.setOnClickListener(v -> {
                String current = allowlistInput.getText().toString();
                List<String> lines = new ArrayList<>(Arrays.asList(current.split("\n")));
                lines.removeIf(String::isEmpty);
                if (!lines.contains(sender)) {
                    lines.add(sender);
                }
                allowlistInput.setText(TextUtils.join("\n", lines));
                Toast.makeText(this, R.string.sender_added_to_field, Toast.LENGTH_SHORT).show();
            });
            observedContainer.addView(add);
        }
    }

    private void saveSettings() {
        String url = urlInput.getText().toString().trim();
        if (url.isEmpty()) {
            urlInput.setError(getString(R.string.error_empty_url));
            return;
        }
        if (!MetaHttpClient.isValidConfiguredUrl(url)) {
            urlInput.setError(getString(R.string.error_wrong_url));
            return;
        }
        List<String> lines = new ArrayList<>();
        for (String line : allowlistInput.getText().toString().split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if ("*".equals(trimmed)) {
                allowlistInput.setError(getString(R.string.error_wildcard_sender));
                return;
            }
            if (trimmed.contains(" ") || trimmed.contains("\t")) {
                allowlistInput.setError(getString(R.string.error_sender_whitespace));
                return;
            }
            lines.add(trimmed);
        }
        Set<String> allowlist = new LinkedHashSet<>(MetaFilter.dedupeAllowlist(lines));
        // The allowlist may be empty on purpose: the app then forwards nothing.
        try {
            SecureStore.setWorkerUrl(this, url);
            SecureStore.setAllowlist(this, allowlist);
            if (!allowlist.isEmpty()) {
                SecureStore.clearObservedSenders(this);
            }
        } catch (Exception e) {
            String keyError = SecureStore.getLastKeystoreError();
            Toast.makeText(this,
                    keyError == null || keyError.isEmpty()
                            ? "Could not save: secure storage is unavailable on this device."
                            : "Could not save: " + keyError,
                    Toast.LENGTH_LONG).show();
            return;
        }
        Toast.makeText(this, R.string.settings_saved_toast, Toast.LENGTH_SHORT).show();
        refreshObserved();
        finish();
    }
}
