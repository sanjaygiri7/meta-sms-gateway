package tech.bogomolov.incomingsmsgateway;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;

import androidx.work.Data;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;

/**
 * Manifest-declared SMS receiver, guarded by BROADCAST_SMS in the manifest so
 * only the system can trigger it.
 *
 * <p>Fail-closed Meta-only filter: an SMS is forwarded only when BOTH the
 * sender is explicitly allowlisted AND the body matches the Meta template.
 * Rejected messages are discarded locally. No rejected message, sender,
 * diagnostic sample or body is ever uploaded, logged or stored, except for
 * the local-only observed-sender list (sender ID only, no body) shown in
 * Settings while the allowlist is empty, so the user can approve a sender
 * manually. Nothing is trusted automatically.
 *
 * <p>Accepted payloads are encrypted before enqueueing: WorkManager input
 * Data holds only ciphertext and a random event ID, never plaintext.
 */
public class SmsBroadcastReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        Bundle bundle = intent.getExtras();
        if (bundle == null) {
            return;
        }
        Object[] pdus = (Object[]) bundle.get("pdus");
        if (pdus == null || pdus.length == 0) {
            return;
        }
        String format = bundle.getString("format");
        StringBuilder content = new StringBuilder();
        SmsMessage first = null;
        for (Object pdu : pdus) {
            SmsMessage message;
            try {
                message = format != null
                        ? SmsMessage.createFromPdu((byte[]) pdu, format)
                        : SmsMessage.createFromPdu((byte[]) pdu);
            } catch (Exception e) {
                Log.e("SmsGateway", "sms parse failed");
                return;
            }
            if (first == null) {
                first = message;
            }
            String part = message.getDisplayMessageBody();
            if (part != null) {
                content.append(part);
            }
        }
        if (first == null) {
            return;
        }
        String sender = first.getOriginatingAddress();
        String body = content.toString();
        if (sender == null || sender.isEmpty() || body.isEmpty()) {
            return;
        }

        Set<String> allowlist;
        try {
            allowlist = SecureStore.getAllowlist(context);
        } catch (Exception e) {
            Log.e("SmsGateway", "config unavailable, discarding");
            return;
        }

        if (allowlist.isEmpty()) {
            // Local-only setup help. Sender ID only, never the body, never uploaded.
            try {
                SecureStore.recordObservedSender(context, sender);
            } catch (Exception ignored) {
                // Diagnostic storage must never break the fail-closed path.
            }
            return;
        }

        if (!MetaFilter.accepts(allowlist, sender, body)) {
            return;
        }

        // Both conditions held. Build the exact payload, encrypt it, enqueue ciphertext only.
        String eventId = UUID.randomUUID().toString();
        String receivedAt = Instant.ofEpochMilli(first.getTimestampMillis()).toString();
        String payload = JsonEscape.buildPayload(eventId, sender, body, receivedAt);
        byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
        String ciphertext;
        try {
            ciphertext = SecureStore.encryptPayload(context, payloadBytes);
            SecureStore.incrementAcceptedCount(context);
        } catch (Exception e) {
            Log.e("SmsGateway", "payload encryption failed, discarding");
            return;
        } finally {
            Arrays.fill(payloadBytes, (byte) 0);
        }

        Data data = new Data.Builder()
                .putString(RequestWorker.DATA_CIPHERTEXT, ciphertext)
                .putString(RequestWorker.DATA_EVENT_ID, eventId)
                .putInt(RequestWorker.DATA_MAX_RETRIES, 3)
                .build();
        RequestWorker.enqueue(context, data);
    }
}
