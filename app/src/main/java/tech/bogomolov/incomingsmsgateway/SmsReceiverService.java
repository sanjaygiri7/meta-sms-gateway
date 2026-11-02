package tech.bogomolov.incomingsmsgateway;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import androidx.annotation.Nullable;

/**
 * Foreground indicator only. SMS delivery is handled by the manifest-declared
 * SmsBroadcastReceiver. This service makes no network requests: the heartbeat
 * feature from the original app has been removed entirely.
 *
 * <p>Defensive by design: if the foreground notification cannot be posted
 * (system refusal, missing channel, or any other failure), the service
 * stops itself instead of crashing the app process. The SMS receiver
 * keeps working without this indicator service.
 */
public class SmsReceiverService extends Service {

    private static final String CHANNEL_ID = "SmsDefault";

    private boolean foregroundStarted;

    @Override
    public void onCreate() {
        super.onCreate();
        startForegroundSafe();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForegroundSafe();
        return START_STICKY;
    }

    private void startForegroundSafe() {
        if (foregroundStarted) {
            return;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        try {
            NotificationManager notificationManager =
                    getSystemService(NotificationManager.class);
            if (notificationManager == null) {
                stopSelf();
                return;
            }
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    getText(R.string.notification_channel),
                    NotificationManager.IMPORTANCE_LOW);
            notificationManager.createNotificationChannel(channel);
            Notification.Builder builder = new Notification.Builder(this, CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_f)
                    .setOngoing(true);
            try {
                builder.setColor(getColor(R.color.colorPrimary));
            } catch (Exception ignored) {
                // Colour is cosmetic; a missing resource must not kill the service.
            }
            startForeground(1, builder.build());
            foregroundStarted = true;
        } catch (Exception e) {
            // Never let the indicator service crash the app: stop quietly.
            stopSelf();
        }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
