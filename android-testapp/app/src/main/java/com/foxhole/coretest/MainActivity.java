package com.foxhole.coretest;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * Requests VPN consent, then hands the run parameters to {@link FoxholeTestVpnService}.
 *
 * The service is BIND_VPN_SERVICE-protected, so `adb shell am startservice` cannot reach it;
 * this activity is the shell-reachable entry point. Every extra is forwarded verbatim:
 *   --es cmd start|stop|stats|drain|netchange|lifecycle|soak|policy|lanes|exit|reach|flood
 *             |i2pstub|i2pstub-stop|i2presolve|i2pconnect|continuity|killdl|naiveudp
 *             |forcekill|lanclient|churn|invariants
 *
 * `invariants` is the only command that needs no extras at all — it carries its own
 * `direct` engine config, because its subject is the JNI boundary rather than a profile.
 * Driven by scripts/device-abi-invariants.sh.
 *   --es cfg  /path/to/engine-config.json   (never the config body itself)
 *   --es policy /path/to/policy.json        (for cmd=policy)
 *   --ez with_network true|false   --ei cycles N   --ei soak N   --ei drain_max N
 *   --ei minutes N   --ei interval N        (for cmd=soak)
 *   --es host H --ei socks_port N --ei http_port N          (for cmd=lanclient)
 *   --es host name.i2p                      (for cmd=i2pconnect|lanclient)
 *   --ez probe true|false
 */
public class MainActivity extends Activity {
    private static final String TAG = "FoxholeCoreTest";
    private static final int REQ_VPN = 1;

    private Intent pending;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setText("Foxhole Core Test");
        setContentView(tv);

        pending = new Intent(this, FoxholeTestVpnService.class);
        Intent in = getIntent();
        if (in != null) {
            copyString(in, "cmd");
            copyString(in, "cfg");
            copyString(in, "policy");
            pending.putExtra("with_network", in.getBooleanExtra("with_network", false));
            pending.putExtra("confirm", in.getBooleanExtra("confirm", true));
            pending.putExtra("timeout", in.getIntExtra("timeout", 45));
            pending.putExtra("probe", in.getBooleanExtra("probe", true));
            pending.putExtra("cycles", in.getIntExtra("cycles", 1));
            pending.putExtra("soak", in.getIntExtra("soak", 20));
            pending.putExtra("drain_max", in.getIntExtra("drain_max", 64));
            pending.putExtra("minutes", in.getIntExtra("minutes", 30));
            pending.putExtra("interval", in.getIntExtra("interval", 60));
            pending.putExtra("port", in.getIntExtra("port", 4447));
            pending.putExtra("socks_port", in.getIntExtra("socks_port", 11080));
            pending.putExtra("http_port", in.getIntExtra("http_port", 13128));
            pending.putExtra("mib", in.getIntExtra("mib", 32));
            pending.putExtra("idle", in.getIntExtra("idle", 360));
            copyString(in, "url");
            copyString(in, "host");
        }

        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            Log.i(TAG, "VPN consent required");
            startActivityForResult(prepare, REQ_VPN);
        } else {
            deliver();
        }
    }

    private void copyString(Intent in, String key) {
        String value = in.getStringExtra(key);
        if (value != null) {
            pending.putExtra(key, value);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            deliver();
        } else {
            Log.e(TAG, "VPN permission denied");
            finish();
        }
    }

    private void deliver() {
        Log.i(TAG, "CMD dispatch cmd=" + pending.getStringExtra("cmd"));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(pending);
        } else {
            startService(pending);
        }
        // Finish so the next `am start` runs onCreate again instead of being a no-op.
        finish();
    }
}
