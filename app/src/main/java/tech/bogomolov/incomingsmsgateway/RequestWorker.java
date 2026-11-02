package tech.bogomolov.incomingsmsgateway;

import android.content.Context;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.Data;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/**
 * Delivers one accepted Meta SMS to the configured Cloudflare Worker.
 *
 * <p>Input Data holds only AES-GCM ciphertext and a random event ID. The
 * payload is decrypted inside the worker immediately before transmission,
 * signed with a fresh timestamp and nonce for EVERY attempt (including
 * retries), and cleared from memory as soon as practical. The event ID is
 * unchanged across retries so the Worker can deduplicate.
 *
 * <p>Retry policy: network failures and 5xx retry with exponential backoff,
 * at most 3 attempts. Permanent 4xx and 3xx responses fail without retry and
 * without storing the payload anywhere.
 */
public class RequestWorker extends Worker {

    public static final String DATA_CIPHERTEXT = "CIPHERTEXT";
    public static final String DATA_EVENT_ID = "EVENT_ID";
    public static final String DATA_MAX_RETRIES = "MAX_RETRIES";

    public RequestWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    public static void enqueue(Context context, Data data) {
        Constraints constraints = new Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build();
        OneTimeWorkRequest workRequest = new OneTimeWorkRequest.Builder(RequestWorker.class)
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,
                        OneTimeWorkRequest.MIN_BACKOFF_MILLIS, TimeUnit.MILLISECONDS)
                .setInputData(data)
                .build();
        WorkManager.getInstance(context).enqueue(workRequest);
    }

    @NonNull
    @Override
    public Result doWork() {
        int maxRetries = getInputData().getInt(DATA_MAX_RETRIES, 3);
        if (getRunAttemptCount() > maxRetries) {
            return Result.failure();
        }
        String ciphertext = getInputData().getString(DATA_CIPHERTEXT);
        if (ciphertext == null || ciphertext.isEmpty()) {
            return Result.failure();
        }

        byte[] rawBody;
        String workerUrl;
        String deviceId;
        byte[] secret;
        try {
            rawBody = SecureStore.decryptPayload(getApplicationContext(), ciphertext);
            workerUrl = SecureStore.getWorkerUrl(getApplicationContext());
            deviceId = SecureStore.getDeviceId(getApplicationContext());
            secret = SecureStore.getOrCreateHmacSecret(getApplicationContext());
        } catch (Exception e) {
            Log.e("RequestWorker", "decrypt or config failed");
            return Result.failure();
        }
        if (workerUrl == null || !MetaHttpClient.isValidConfiguredUrl(workerUrl)
                || !MetaHttpClient.isAllowedEndpoint(workerUrl, workerUrl)) {
            Arrays.fill(rawBody, (byte) 0);
            Arrays.fill(secret, (byte) 0);
            return Result.failure();
        }

        try {
            // Fresh timestamp and nonce for every attempt, including retries.
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            String nonce = Signing.freshNonce();
            String signature = Signing.sign(secret, timestamp, nonce, rawBody);
            int code;
            try {
                code = MetaHttpClient.post(workerUrl, rawBody, deviceId, timestamp, nonce, signature);
            } catch (IOException e) {
                Log.e("RequestWorker", "network failure");
                return Result.retry();
            }
            MetaHttpClient.Outcome outcome = MetaHttpClient.classify(code);
            if (outcome == MetaHttpClient.Outcome.SUCCESS) {
                return Result.success();
            }
            if (outcome == MetaHttpClient.Outcome.RETRY) {
                return Result.retry();
            }
            return Result.failure();
        } finally {
            Arrays.fill(rawBody, (byte) 0);
            Arrays.fill(secret, (byte) 0);
        }
    }
}
