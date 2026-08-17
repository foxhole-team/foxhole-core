package com.foxhole.coretest;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.foxhole.core.runtime.FoxholeNativeEngine;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

/**
 * VpnService harness that drives the experimental Rust core end-to-end on-device.
 *
 * The EngineConfig is NEVER compiled into this app: it is read from a file path handed over
 * in the start intent, so subscription credentials stay out of source, out of argv and out of
 * logcat. The service only ever logs redacted counters, event kinds and probe verdicts.
 *
 * The core calls {@link #protectSocket(int)} for its own outbound sockets so they bypass the
 * tunnel; this app's own probe requests are NOT protected, so they flow through the TUN and
 * return the server's exit IP — the on-device proof.
 */
public class FoxholeTestVpnService extends VpnService {
    private static final String TAG = "FoxholeCoreTest";
    private static final String CHANNEL_ID = "foxcore_diagnostics";
    private static final int NOTIFICATION_ID = 4701;

    /**
     * Names expected to be refused by dns.blocklist in the pushed config. All three resolve
     * normally on this device when the blocklist is absent, so a failure here is attributable
     * to the blocklist and not to a name that never existed.
     */
    private static final String DNS_BLOCKED_SUFFIX = "www.example.org";
    private static final String DNS_BLOCKED_EXACT = "example.net";
    private static final String DNS_ALLOWED = "example.com";

    /**
     * The LAN proxy credentials. Test values on purpose: they are the ones a second machine
     * would be told, and the scenario's whole point is what happens to clients that do NOT
     * present them.
     */
    private static final String LAN_USERNAME = "foxlan";
    private static final String LAN_PASSWORD = "foxhole-lan-secret";

    /**
     * Echo used to identify which upstream actually carried a LAN session.
     *
     * <p>A 200 from an ordinary site proves only that something answered. The preset claims
     * to choose between the VPN and Tor, and the only way to see the difference from the
     * client side is to ask what exit the request came out of — the same fingerprint the
     * tunnel probes report, so the two are directly comparable.
     */
    private static final String LAN_EXIT_ECHO = "api.ipify.org";

    /**
     * The Tor Project's own onion service, used as the `.onion` counterpart to an eepsite.
     *
     * <p>Picked because it answers plain HTTP on port 80 and is about as long-lived as a
     * hidden service gets: when the point of a run is "Tor still works while I2P is stopped",
     * the destination going away would look exactly like the failure being tested for.
     */
    private static final String ONION_ECHO =
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    /**
     * Independent exit-IP echoes. Three, run by three different operators: one service
     * agreeing with itself proves nothing, and two leaves no tie-breaker when they disagree.
     */
    private static final String[][] EXIT_ECHOES = {
            {"ipify", "https://api.ipify.org"},
            {"ifconfig", "https://ifconfig.me/ip"},
            {"icanhazip", "https://icanhazip.com"},
    };

    private ParcelFileDescriptor tun;
    private volatile long handle = 0;
    private volatile boolean monitorRun = false;
    private int protectCalls = 0;
    private int protectOk = 0;
    private volatile java.net.ServerSocket i2pStub;
    private volatile int i2pStubCalls = 0;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "FoxCore diagnostics",
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Headless VPN core verification");
        manager.createNotificationChannel(channel);

        Intent launch = new Intent(this, MainActivity.class);
        PendingIntent pending = PendingIntent.getActivity(
                this,
                0,
                launch,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("FoxCore diagnostics")
                .setContentText("VPN core test is running")
                .setContentIntent(pending)
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    /** Called from native code before each outbound connect. */
    public boolean protectSocket(int fd) {
        boolean ok = protect(fd);
        synchronized (this) {
            protectCalls++;
            if (ok) {
                protectOk++;
            }
            // Log only the first few: one line per socket floods the run.
            if (protectCalls <= 5) {
                Log.i(TAG, "PROTECT fd=" + fd + " ok=" + ok);
            }
        }
        return ok;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        final String cmd = intent != null && intent.getStringExtra("cmd") != null
                ? intent.getStringExtra("cmd") : "start";
        final String cfgPath = intent != null ? intent.getStringExtra("cfg") : null;
        final boolean withNetwork = intent != null && intent.getBooleanExtra("with_network", false);
        final int cycles = intent != null ? intent.getIntExtra("cycles", 1) : 1;
        final boolean probe = intent == null || intent.getBooleanExtra("probe", true);
        final int drainMax = intent != null ? intent.getIntExtra("drain_max", 64) : 64;
        final int soakSeconds = intent != null ? intent.getIntExtra("soak", 20) : 20;
        final String policyPath = intent != null ? intent.getStringExtra("policy") : null;
        final int minutes = intent != null ? intent.getIntExtra("minutes", 30) : 30;
        final int overlayTimeout = intent != null ? intent.getIntExtra("timeout", 45) : 45;
        final int intervalSeconds = intent != null ? intent.getIntExtra("interval", 60) : 60;

        new Thread(() -> {
            try {
                switch (cmd) {
                    case "stop":
                        stopEngine();
                        break;
                    case "drain":
                        logDrain(drainMax);
                        break;
                    case "stats":
                        logStats("ONDEMAND");
                        logLanes("ONDEMAND");
                        break;
                    case "policy":
                        reloadPolicy(policyPath);
                        break;
                    case "lanes":
                        logLanes("ONDEMAND");
                        break;
                    case "soak":
                        soak(cfgPath, withNetwork, minutes, intervalSeconds);
                        break;
                    case "exit":
                        exitIpProbes("ondemand");
                        break;
                    case "i2pstub":
                        startI2pStub(intent != null ? intent.getIntExtra("port", 4447) : 4447);
                        break;
                    case "i2pstub-stop":
                        stopI2pStub();
                        break;
                    case "i2pconnect":
                        // Resolving an .i2p name only proves fake-IP answered. The lane is
                        // only exercised when a flow is actually opened against it.
                        overlayFetchProbe(intent != null && intent.getStringExtra("host") != null
                                ? intent.getStringExtra("host") : "stats.i2p", "I2P_CONNECT",
                                overlayTimeout);
                        break;
                    case "onionconnect":
                        // The same question asked of the other overlay, so a run with one
                        // stopped shows whether the other still answers.
                        overlayFetchProbe(intent != null && intent.getStringExtra("host") != null
                                ? intent.getStringExtra("host") : ONION_ECHO, "ONION_CONNECT",
                                overlayTimeout);
                        break;
                    case "i2presolve":
                        // `.i2p` must never reach clearnet, and must fail closed when the
                        // loopback process is absent.
                        resolveProbe("stats.i2p", true);
                        Thread.sleep(2000);
                        logStats("AFTER_I2P_RESOLVE");
                        logLanes("AFTER_I2P_RESOLVE");
                        logDrain(64);
                        break;
                    case "continuity":
                        continuityScenario(policyPath, soakSeconds);
                        break;
                    case "killdl":
                        killSwitchDuringDownload(policyPath,
                                intent != null && intent.getStringExtra("url") != null
                                        ? intent.getStringExtra("url")
                                        : "https://speed.cloudflare.com/__down?bytes=52428800");
                        break;
                    case "lanclient":
                        lanClient(intent != null ? intent.getStringExtra("host") : null,
                                intent != null ? intent.getIntExtra("socks_port", 11080) : 0,
                                intent != null ? intent.getIntExtra("http_port", 13128) : 0);
                        break;
                    case "churn":
                        stopUnderChurn(cfgPath, withNetwork, cycles);
                        break;
                    case "naiveudp":
                        naiveUdpProbe();
                        break;
                    case "upload":
                        upload(intent != null ? intent.getIntExtra("mib", 32) : 32,
                                intent != null && intent.getStringExtra("url") != null
                                        ? intent.getStringExtra("url")
                                        : "https://speed.cloudflare.com/__up");
                        break;
                    case "push":
                        pushChannel(intent != null && intent.getStringExtra("host") != null
                                        ? intent.getStringExtra("host") : "imap.gmail.com",
                                intent != null ? intent.getIntExtra("port", 143) : 143,
                                intent != null ? intent.getIntExtra("idle", 360) : 360);
                        break;
                    case "forcekill":
                        Log.i(TAG, "FORCEKILL result="
                                + FoxholeNativeEngine.nativeForceKill(handle));
                        handle = 0;
                        break;
                    case "netchange":
                        netChange();
                        break;
                    case "reach":
                        reachProbe(cfgPath);
                        break;
                    case "flood":
                        flood(cfgPath, withNetwork, cycles);
                        break;
                    case "baseline":
                        // Control run: no TUN, no core. Whatever IP this reports is the
                        // device's direct exit, which the tunnelled run must differ from.
                        Log.i(TAG, "BASELINE begin (no tunnel)");
                        exitIpProbes("baseline");
                        resolveProbe(DNS_BLOCKED_SUFFIX, false);
                        Log.i(TAG, "BASELINE end");
                        break;
                    case "lifecycle":
                        lifecycle(cfgPath, cycles, withNetwork);
                        break;
                    case "invariants":
                        abiInvariants();
                        break;
                    default:
                        runOnce(cfgPath, withNetwork, probe, soakSeconds, drainMax);
                        break;
                }
            } catch (Throwable t) {
                // The message, not just the class: a bare IllegalStateException from the
                // JNI boundary is the difference between "no Tor in this build" and
                // "this directory is not writable", and those need different fixes.
                Log.e(TAG, "CMD " + cmd + " failed=" + t.getClass().getSimpleName()
                        + " msg=" + t.getMessage());
            }
        }, "foxhole-test-cmd").start();
        return START_NOT_STICKY;
    }

    private String readConfig(String cfgPath) throws Exception {
        if (cfgPath == null) {
            throw new IllegalArgumentException("no --es cfg <path> supplied");
        }
        File f = new File(cfgPath);
        byte[] buf = new byte[(int) f.length()];
        try (FileInputStream in = new FileInputStream(f)) {
            int read = 0;
            while (read < buf.length) {
                int n = in.read(buf, read, buf.length - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
        }
        String json = new String(buf, StandardCharsets.UTF_8).trim();
        Log.i(TAG, "CONFIG loaded bytes=" + json.length());
        return json;
    }

    /** Establish the TUN and hand the fd to the core. Returns the handle (0 on failure). */
    private long startEngine(String cfgPath, boolean withNetwork) throws Exception {
        String config = readConfig(cfgPath);
        // MUST be sampled before establish(): once the TUN is up, getActiveNetwork() returns
        // the VPN itself, and binding the core's outbound sockets to that handle routes them
        // back into the tunnel they are supposed to escape.
        final Network underlying = activeNetwork();
        final long networkHandle = underlying == null ? 0 : underlying.getNetworkHandle();
        // Logged as its own line, before establish(), because the failure it guards against
        // is invisible in every other counter: sample the handle afterwards and protectSocket
        // returns true for thousands of sockets while every dial fails and bytes stay zero.
        Log.i(TAG, "NET_HANDLE sampled_pre_establish=true present=" + (networkHandle != 0)
                + " is_vpn=" + isVpn(underlying));
        // The VpnService TUN must carry the same address/MTU the EngineConfig declares,
        // otherwise (WireGuard especially) the peer sees a source it never allocated.
        org.json.JSONObject tunCfg = new org.json.JSONObject(config).getJSONObject("tun");
        String tunIp = tunCfg.optString("ipv4", "10.0.0.2");
        int mtu = tunCfg.optInt("mtu", 1400);
        Builder b = new Builder();
        b.setSession("FoxholeCoreTest");
        b.setMtu(mtu);
        b.addAddress(tunIp, 32);
        b.addDnsServer("1.1.1.1");
        b.addRoute("0.0.0.0", 0);
        if (underlying != null) {
            b.setUnderlyingNetworks(new Network[] {underlying});
        }
        // Stated explicitly: the relay refuses at start when the tun advertises a
        // family the packet tunnel has no pair for, so what is advertised here is
        // half of that decision.
        String tunIpv6 = tunCfg.optString("ipv6", "");
        if (!tunIpv6.isEmpty()) {
            b.addAddress(tunIpv6, 128);
            b.addRoute("::", 0);
        }
        Log.i(TAG, "TUN ip=" + tunIp + " mtu=" + mtu
                + " ipv6=" + (tunIpv6.isEmpty() ? "none" : tunIpv6)
                + " routes=" + (tunIpv6.isEmpty() ? "v4only" : "v4+v6"));
        tun = b.establish();
        if (tun == null) {
            Log.e(TAG, "establish() returned null");
            return 0;
        }
        int fd = tun.detachFd();
        // Diagnostic for the core's bootstrap-DNS path: Network.getAllByName() is the Java
        // twin of android_getaddrinfofornetwork(). If this also hangs, the TUN we just
        // established is swallowing network-pinned DNS and the core is not at fault.
        networkPinnedDnsProbe(underlying);
        Log.i(TAG, "VERSION " + FoxholeNativeEngine.nativeVersion()
                + " abi=" + FoxholeNativeEngine.nativeAbiVersion());
        long h;
        if (withNetwork) {
            Log.i(TAG, "START with pre-TUN network_handle_present=" + (networkHandle != 0));
            h = FoxholeNativeEngine.nativeStartWithNetwork(fd, config, networkHandle, this);
        } else {
            h = FoxholeNativeEngine.nativeStart(fd, config, this);
        }
        Log.i(TAG, "START handle=" + (h != 0 ? "nonzero" : "ZERO"));
        return h;
    }

    /**
     * Plain TCP connect to each outbound endpoint with NO tunnel up, to separate "the core
     * cannot dial" from "this network cannot reach the endpoint". Logs protocol + result only.
     */
    private void reachProbe(String cfgPath) throws Exception {
        String json = readConfig(cfgPath);
        org.json.JSONObject root = new org.json.JSONObject(json);
        org.json.JSONObject out = root.getJSONObject("outbound");
        if ("selector".equals(out.optString("type"))) {
            org.json.JSONArray members = out.getJSONArray("members");
            for (int i = 0; i < members.length(); i++) {
                connectProbe(members.getJSONObject(i).getJSONObject("outbound"));
            }
        } else {
            connectProbe(out);
        }
    }

    private void connectProbe(org.json.JSONObject o) {
        String type = o.optString("type");
        String host = o.optString("server_ip", o.optString("server"));
        int port = o.optInt("port");
        long t0 = System.currentTimeMillis();
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress(host, port), 8000);
            Log.i(TAG, "REACH type=" + type + " tcp=OPEN ms=" + (System.currentTimeMillis() - t0));
        } catch (Exception e) {
            Log.i(TAG, "REACH type=" + type + " tcp=FAIL/" + e.getClass().getSimpleName()
                    + " ms=" + (System.currentTimeMillis() - t0));
        }
    }

    /** Resolve a control name pinned to the underlying network, with the TUN already up. */
    private void networkPinnedDnsProbe(Network n) {
        long t0 = System.currentTimeMillis();
        try {
            if (n == null) {
                Log.i(TAG, "BOOTSTRAP_DNS no active network");
                return;
            }
            InetAddress[] a = n.getAllByName("example.com");
            Log.i(TAG, "BOOTSTRAP_DNS network-pinned resolve OK count=" + a.length
                    + " ms=" + (System.currentTimeMillis() - t0));
        } catch (Throwable t) {
            Log.i(TAG, "BOOTSTRAP_DNS network-pinned resolve FAILED " + t.getClass().getSimpleName()
                    + " ms=" + (System.currentTimeMillis() - t0));
        }
    }

    /**
     * The network the device actually uses to reach the internet. Once our own TUN is up,
     * getActiveNetwork() reports the VPN, so prefer an explicit non-VPN WIFI/CELLULAR pick.
     */
    /** True when the picked network is a VPN — which, pre-establish, means we picked wrong. */
    private boolean isVpn(Network network) {
        if (network == null) {
            return false;
        }
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            return caps != null
                    && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN);
        } catch (Throwable t) {
            return false;
        }
    }

    private Network activeNetwork() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            for (Network n : cm.getAllNetworks()) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                if (caps == null) {
                    continue;
                }
                boolean notVpn = !caps.hasTransport(
                        android.net.NetworkCapabilities.TRANSPORT_VPN);
                boolean internet = caps.hasCapability(
                        android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET);
                boolean validated = caps.hasCapability(
                        android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED);
                if (notVpn && internet && validated) {
                    return n;
                }
            }
            return cm.getActiveNetwork();
        } catch (Throwable t) {
            Log.e(TAG, "network lookup failed=" + t.getClass().getSimpleName());
            return null;
        }
    }

    private void runOnce(String cfgPath, boolean withNetwork, boolean probe,
                         int soakSeconds, int drainMax) throws Exception {
        if (!stopEngine()) {
            Log.e(TAG, "RESULT previous_stop_incomplete");
            return;
        }
        handle = startEngine(cfgPath, withNetwork);
        if (handle == 0) {
            Log.e(TAG, "RESULT start_failed");
            return;
        }
        logStats("AFTER_START");
        startMonitor(drainMax);
        Thread.sleep(3000);
        if (probe) {
            dnsProbes();
            exitIpProbes("tunnel");
        }
        Thread.sleep(soakSeconds * 1000L);
        logStats("AFTER_SOAK");
        logLanes("AFTER_SOAK");
        logDrain(drainMax);
        Log.i(TAG, "PROTECT_SUMMARY calls=" + protectCalls + " ok=" + protectOk);
        stopMonitor();
    }

    /**
     * Execute the JNI boundary's Android-only branches and print a verdict for each.
     *
     * <p>Unlike every other command here this one takes nothing: no `--es cfg`, no server,
     * no subscription. It is the run that answers docs/24 §9 — "everything under
     * cfg(target_os = "android") was read and cross-checked and never executed" — so its
     * whole value is being runnable on a borrowed phone with one command, without first
     * arranging a working profile.
     *
     * <p>The network handle is sampled before {@code establish()} for the same reason
     * {@link #startEngine} does it: afterwards {@code getActiveNetwork()} is the VPN, and
     * pinning the core's sockets to that handle routes them into the tunnel they exist to
     * escape. Here it would also mean `android_setsocknetwork` — one of the branches under
     * test — being handed the wrong network and still returning success.
     */
    private void abiInvariants() throws Exception {
        stopEngine();
        final Network underlying = activeNetwork();
        final long networkHandle = underlying == null ? 0 : underlying.getNetworkHandle();
        Log.i(TAG, "NET_HANDLE sampled_pre_establish=true present=" + (networkHandle != 0)
                + " is_vpn=" + isVpn(underlying));
        NativeInvariantSmoke.run(() -> {
            Builder b = new Builder();
            b.setSession("FoxholeCoreTest invariants");
            b.setMtu(1400);
            b.addAddress("10.0.0.2", 32);
            b.addDnsServer("1.1.1.1");
            b.addRoute("0.0.0.0", 0);
            if (underlying != null) {
                b.setUnderlyingNetworks(new Network[] {underlying});
            }
            return b.establish();
        }, networkHandle);
    }

    /**
     * Overflow the bounded event queue on purpose: start, never drain, resolve `count`
     * distinct blocked names, then drain once. The queue holds 512, so a larger count
     * must come back with a non-zero `dropped`.
     */
    private void flood(String cfgPath, boolean withNetwork, int count) throws Exception {
        if (count <= 1) {
            count = 900;
        }
        if (!stopEngine()) {
            Log.e(TAG, "FLOOD previous_stop_incomplete");
            return;
        }
        handle = startEngine(cfgPath, withNetwork);
        if (handle == 0) {
            Log.e(TAG, "FLOOD start_failed");
            return;
        }
        // Deliberately no monitor thread: nothing drains while the queue fills.
        // Raw DNS datagrams straight at the advertised resolver: Android's own
        // resolver rate-limits and caches, which made it impossible to outrun the
        // 512-slot queue through InetAddress.
        final int n = count;
        int sent = 0;
        try (java.net.DatagramSocket sock = new java.net.DatagramSocket()) {
            sock.setSoTimeout(1);
            InetAddress resolver = InetAddress.getByName("1.1.1.1");
            for (int i = 0; i < n; i++) {
                byte[] q = dnsQuery("x" + i + ".flood.example.org", i & 0xffff);
                sock.send(new java.net.DatagramPacket(q, q.length, resolver, 53));
                sent++;
                try {
                    // Drain any reply without blocking the send loop.
                    sock.receive(new java.net.DatagramPacket(new byte[512], 512));
                } catch (Exception ignored) {
                }
            }
        }
        Log.i(TAG, "FLOOD issued=" + sent);
        Thread.sleep(3000);
        logStats("AFTER_FLOOD");
        // Parse, never regex: these batches are large and a greedy pattern over them
        // overflows the stack.
        for (int max : new int[] {16, 1000, 1000}) {
            String batch = FoxholeNativeEngine.nativeDrainEvents(handle, max);
            org.json.JSONObject o = new org.json.JSONObject(batch);
            Log.i(TAG, "FLOOD drain(max=" + max + ") events="
                    + o.getJSONArray("events").length()
                    + " dropped=" + o.getLong("dropped")
                    + " bytes=" + batch.length());
        }
        stopEngine();
    }

    /** Minimal DNS A-record query wire format. */
    private static byte[] dnsQuery(String name, int id) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(id >> 8);
        out.write(id & 0xff);
        out.write(0x01);
        out.write(0x00); // standard query, recursion desired
        out.write(0x00);
        out.write(0x01); // QDCOUNT=1
        for (int i = 0; i < 6; i++) {
            out.write(0x00); // AN/NS/AR counts
        }
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0x00);
        out.write(0x00);
        out.write(0x01); // QTYPE=A
        out.write(0x00);
        out.write(0x01); // QCLASS=IN
        return out.toByteArray();
    }

    /** start -> stop -> start cycles, reporting thread/fd counts to expose leaks. */
    private void lifecycle(String cfgPath, int cycles, boolean withNetwork) throws Exception {
        for (int i = 1; i <= cycles; i++) {
            Log.i(TAG, "LIFECYCLE cycle=" + i + " phase=pre " + processFootprint());
            handle = startEngine(cfgPath, withNetwork);
            if (handle == 0) {
                Log.e(TAG, "LIFECYCLE cycle=" + i + " start_failed");
                return;
            }
            Thread.sleep(4000);
            logStats("LIFECYCLE_" + i);
            Log.i(TAG, "LIFECYCLE cycle=" + i + " phase=running " + processFootprint());
            if (!stopEngine()) {
                Log.e(TAG, "LIFECYCLE cycle=" + i + " stop_incomplete");
                return;
            }
            Thread.sleep(2000);
            Log.i(TAG, "LIFECYCLE cycle=" + i + " phase=post " + processFootprint());
        }
        Log.i(TAG, "LIFECYCLE done");
    }


    /**
     * Bring up the LAN proxy on the current Wi-Fi and report what other machines can reach.
     *
     * <p>The interesting assertions are all negative: an anonymous client must be refused,
     * the listeners must not be reachable on the mobile interface, and a network change must
     * invalidate the credentials rather than carry them to the new network.
     */



    /**
     * The client half of the LAN contract, driven from the device itself.
     *
     * <p>A client on this device aiming at this device's own Wi-Fi address is a real client
     * in that Wi-Fi: it opens an ordinary TCP connection to an address the AP hands out, and
     * the listener cannot tell it apart from a laptop's. What it does NOT cover is the path
     * over the air — a second machine would also prove the AP forwards the frames and that no
     * client-isolation rule stands in the way. Everything below is about the proxy's own
     * decisions, and those are the ones that are the core's to make.
     *
     * <p>Every assertion here is a refusal, except the two that prove the refusals are not
     * simply "nothing works".
     */
    private void lanClient(String host, int socksPort, int httpPort) {
        // The listener is no longer raised from here. The LAN proxy's JNI surface
        // is gone — a proxy is declared as an inbound in the engine config, which
        // is the one way the shipped app has ever done it — so this verifier is
        // told where to aim rather than remembering where it started something.
        String target = host != null ? host : "";
        if (target.isEmpty() || (socksPort == 0 && httpPort == 0)) {
            Log.e(TAG, "LANCLIENT no listener to aim at; pass host= and socks_port=/http_port=");
            return;
        }
        Log.i(TAG, "LANCLIENT target=" + target
                + " socks=" + socksPort + " http=" + httpPort);

        // The bind is the claim: on the Wi-Fi address and nowhere else. Loopback is the
        // cheapest way to falsify a wildcard bind, and the mobile interface is the one that
        // would turn this phone into a proxy reachable from the carrier network.
        Log.i(TAG, "LANCLIENT bind_check loopback_socks=" + probeConnect("127.0.0.1", socksPort)
                + " loopback_http=" + probeConnect("127.0.0.1", httpPort));
        for (String cellular : cellularAddresses()) {
            Log.i(TAG, "LANCLIENT bind_check cellular=" + cellular
                    + " socks=" + probeConnect(cellular, socksPort)
                    + " http=" + probeConnect(cellular, httpPort));
        }

        socksAnonymous(target, socksPort);
        socksSession(target, socksPort, LAN_USERNAME, "not-the-password", "wrong_password");
        socksSession(target, socksPort, "not-the-user", LAN_PASSWORD, "wrong_username");
        socksSession(target, socksPort, LAN_USERNAME, LAN_PASSWORD, "correct");

        httpSession(target, httpPort, null, null, "anonymous");
        httpSession(target, httpPort, LAN_USERNAME, "not-the-password", "wrong_password");
        httpSession(target, httpPort, LAN_USERNAME, LAN_PASSWORD, "correct");
    }

    /** Can a TCP connection be opened at all? Used for the negative bind assertions. */
    private String probeConnect(String host, int port) {
        if (port == 0) {
            return "no-listener";
        }
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), 4000);
            return "CONNECTED";
        } catch (Exception e) {
            return "refused/" + e.getClass().getSimpleName();
        }
    }

    /** Addresses on the modem interfaces, if the device has a mobile connection up. */
    private java.util.List<String> cellularAddresses() {
        java.util.List<String> found = new java.util.ArrayList<>();
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                java.net.NetworkInterface nic = interfaces.nextElement();
                String name = nic.getName();
                if (name == null || !(name.startsWith("rmnet") || name.startsWith("ccmni")
                        || name.startsWith("pdp_ip") || name.startsWith("seth_")
                        || name.startsWith("qmimux") || name.startsWith("wwan"))) {
                    continue;
                }
                java.util.Enumeration<InetAddress> addresses = nic.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (address instanceof java.net.Inet4Address && !address.isLoopbackAddress()) {
                        found.add(address.getHostAddress());
                    }
                }
            }
        } catch (Exception e) {
            Log.i(TAG, "LANCLIENT cellular_enumeration_failed=" + e.getClass().getSimpleName());
        }
        return found;
    }

    /**
     * Ask the echo, through an already-established tunnel, which exit the request left from.
     *
     * <p>Reported as the same 6-hex fingerprint the tunnel probes use, so a LAN session can be
     * compared directly against `EXIT_SET`: equal means this session left by the same exit the
     * phone itself uses, different means the preset really did choose another upstream.
     */
    private String exitThroughTunnel(java.net.Socket socket, BufferedReader reader)
            throws Exception {
        socket.getOutputStream().write(("GET / HTTP/1.1\r\nHost: " + LAN_EXIT_ECHO
                + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().flush();
        String statusLine = reader.readLine();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            // headers
        }
        StringBuilder body = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            body.append(line.trim());
        }
        String echoed = body.toString().trim();
        boolean plausible = echoed.length() >= 7 && echoed.length() <= 45
                && echoed.matches("[0-9a-fA-F:.]+");
        return "origin_status=" + statusLine
                + " exit_fp=" + (plausible ? fingerprint(echoed) : "not-an-ip");
    }

    /**
     * Offer only SOCKS5 "no authentication" and see what comes back.
     *
     * <p>`0xff` is the whole point: the server must not have an anonymous method to select,
     * so a client that offers nothing else is told there is no acceptable method and dropped.
     */
    private void socksAnonymous(String host, int port) {
        if (port == 0) {
            return;
        }
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), 8000);
            socket.setSoTimeout(8000);
            socket.getOutputStream().write(new byte[] {0x05, 0x01, 0x00});
            socket.getOutputStream().flush();
            byte[] reply = new byte[2];
            new java.io.DataInputStream(socket.getInputStream()).readFully(reply);
            Log.i(TAG, "LANCLIENT socks case=anonymous method=0x"
                    + Integer.toHexString(reply[1] & 0xff)
                    + " verdict=" + ((reply[0] & 0xff) == 0x05 && (reply[1] & 0xff) == 0xff
                            ? "REFUSED_AS_REQUIRED" : "UNEXPECTED"));
        } catch (Exception e) {
            Log.i(TAG, "LANCLIENT socks case=anonymous error=" + e.getClass().getSimpleName());
        }
    }

    /**
     * A full SOCKS5 username/password session, reported by where it stopped.
     *
     * <p>With the right credentials it must carry bytes end to end; with the wrong ones it
     * must stop at the authentication reply and never reach a CONNECT.
     */
    private void socksSession(String host, int port, String user, String password, String label) {
        if (port == 0) {
            return;
        }
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), 8000);
            socket.setSoTimeout(20000);
            java.io.OutputStream out = socket.getOutputStream();
            java.io.DataInputStream in = new java.io.DataInputStream(socket.getInputStream());

            // Offer both, so the selection itself is observable: the server has to pick 0x02.
            out.write(new byte[] {0x05, 0x02, 0x00, 0x02});
            out.flush();
            byte[] greeting = new byte[2];
            in.readFully(greeting);
            int method = greeting[1] & 0xff;
            if (method != 0x02) {
                Log.i(TAG, "LANCLIENT socks case=" + label + " method=0x"
                        + Integer.toHexString(method) + " verdict=NO_USERPASS_METHOD");
                return;
            }

            byte[] userBytes = user.getBytes(StandardCharsets.UTF_8);
            byte[] passBytes = password.getBytes(StandardCharsets.UTF_8);
            java.io.ByteArrayOutputStream auth = new java.io.ByteArrayOutputStream();
            auth.write(0x01);
            auth.write(userBytes.length);
            auth.write(userBytes);
            auth.write(passBytes.length);
            auth.write(passBytes);
            out.write(auth.toByteArray());
            out.flush();
            byte[] authReply = new byte[2];
            in.readFully(authReply);
            int status = authReply[1] & 0xff;
            if (status != 0x00) {
                Log.i(TAG, "LANCLIENT socks case=" + label + " auth_status=" + status
                        + " verdict=AUTH_REFUSED");
                return;
            }

            byte[] domain = LAN_EXIT_ECHO.getBytes(StandardCharsets.UTF_8);
            java.io.ByteArrayOutputStream request = new java.io.ByteArrayOutputStream();
            request.write(new byte[] {0x05, 0x01, 0x00, 0x03});
            request.write(domain.length);
            request.write(domain);
            request.write(0x00);
            request.write(0x50);
            out.write(request.toByteArray());
            out.flush();
            byte[] head = new byte[4];
            in.readFully(head);
            int rep = head[1] & 0xff;
            if (rep != 0x00) {
                Log.i(TAG, "LANCLIENT socks case=" + label + " connect_rep=0x"
                        + Integer.toHexString(rep) + " verdict=CONNECT_REFUSED");
                return;
            }
            int atyp = head[3] & 0xff;
            in.skipBytes((atyp == 1 ? 4 : atyp == 4 ? 16 : in.readUnsignedByte()) + 2);

            String exit = exitThroughTunnel(socket, new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8)));
            Log.i(TAG, "LANCLIENT socks case=" + label + " auth_status=0 connect_rep=0x0"
                    + " " + exit);
        } catch (Exception e) {
            Log.i(TAG, "LANCLIENT socks case=" + label
                    + " error=" + e.getClass().getSimpleName() + "/" + e.getMessage());
        }
    }

    /**
     * An HTTP CONNECT session. Without credentials the answer must be 407 with a
     * `Proxy-Authenticate: Basic` challenge, and with the wrong ones it must be 407 again —
     * a proxy that distinguishes "unknown user" from "wrong password" is an oracle.
     */
    private void httpSession(String host, int port, String user, String password, String label) {
        if (port == 0) {
            return;
        }
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), 8000);
            socket.setSoTimeout(20000);
            StringBuilder request = new StringBuilder();
            request.append("CONNECT ").append(LAN_EXIT_ECHO).append(":80 HTTP/1.1\r\n");
            request.append("Host: ").append(LAN_EXIT_ECHO).append(":80\r\n");
            if (user != null) {
                String raw = user + ":" + password;
                String encoded = android.util.Base64.encodeToString(
                        raw.getBytes(StandardCharsets.UTF_8), android.util.Base64.NO_WRAP);
                request.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n");
            }
            request.append("\r\n");
            socket.getOutputStream().write(request.toString().getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String statusLine = reader.readLine();
            boolean challenged = false;
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("proxy-authenticate:")) {
                    challenged = true;
                }
            }
            boolean established = statusLine != null && statusLine.contains(" 200");
            String carried = established ? exitThroughTunnel(socket, reader) : "exit_fp=n/a";
            Log.i(TAG, "LANCLIENT http case=" + label + " status=" + statusLine
                    + " challenge=" + challenged + " " + carried);
        } catch (Exception e) {
            Log.i(TAG, "LANCLIENT http case=" + label
                    + " error=" + e.getClass().getSimpleName() + "/" + e.getMessage());
        }
    }

    /**
     * The D13 repro: leave abandoned platform work queued, then time the stop.
     *
     * <p>Ten start/stop cycles never reproduced this, and that is the point. Each new flow
     * costs one attribution call on the blocking pool with a 250 ms timeout; the timeout
     * cancels the future but not the blocking call underneath it, so a burst of short-lived
     * connections leaves a queue that the runtime's own drop then executes. What is measured
     * here is one number: how long nativeStop takes to return.
     */
    private void stopUnderChurn(String cfgPath, boolean withNetwork, int connections)
            throws Exception {
        if (connections <= 0) {
            connections = 300;
        }
        if (!stopEngine()) {
            Log.e(TAG, "CHURN previous_stop_incomplete");
            return;
        }
        handle = startEngine(cfgPath, withNetwork);
        if (handle == 0) {
            Log.e(TAG, "CHURN start_failed");
            return;
        }
        Thread.sleep(2000);
        int opened = 0;
        // Connect and abandon: a completed handshake is not needed, an attribution
        // lookup is, and that happens on the first packet of a new flow.
        for (int i = 0; i < connections; i++) {
            try (java.net.Socket s = new java.net.Socket()) {
                s.connect(new java.net.InetSocketAddress("example.com", 80 + (i % 3)), 150);
            } catch (Exception ignored) {
                // A refused or timed-out connect still created the flow, which is
                // what queues the attribution call.
            }
            opened++;
        }
        Log.i(TAG, "CHURN flows_attempted=" + opened + " " + processFootprint());
        logStats("AFTER_CHURN");
        logLanes("AFTER_CHURN");

        long t0 = System.currentTimeMillis();
        int result = FoxholeNativeEngine.nativeStop(handle);
        long elapsed = System.currentTimeMillis() - t0;
        handle = 0;
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
            }
            tun = null;
        }
        // The whole scenario is this line. STOP_TIMEOUT is 3 s, so anything much
        // past that means a wait in the stop path is still unbounded.
        Log.i(TAG, "CHURN stop_result=" + result + " stop_ms=" + elapsed);
        Thread.sleep(2000);
        Log.i(TAG, "CHURN post_stop " + processFootprint());
    }

    /**
     * Threads, open fds and resident memory — a leak across stop/start shows up here.
     *
     * <p>RSS is included because fds and threads returning to baseline says the handles were
     * released, not that the memory was. A core that returns 86 fds and 16 threads while RSS
     * climbs every cycle is still leaking, just somewhere a file descriptor count cannot see.
     */
    private String processFootprint() {
        int fds = -1;
        int threads = -1;
        long rssKb = -1;
        try {
            File[] fdDir = new File("/proc/self/fd").listFiles();
            fds = fdDir == null ? -1 : fdDir.length;
        } catch (Throwable ignored) {
        }
        try {
            File[] taskDir = new File("/proc/self/task").listFiles();
            threads = taskDir == null ? -1 : taskDir.length;
        } catch (Throwable ignored) {
        }
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream("/proc/self/statm")))) {
            String[] fields = r.readLine().split(" ");
            // statm reports pages; the second field is resident set size.
            rssKb = Long.parseLong(fields[1]) * 4;
        } catch (Throwable ignored) {
        }
        return "fds=" + fds + " threads=" + threads + " rss_kb=" + rssKb;
    }

    /**
     * Per-lane and per-app traffic. Separate from {@link #logStats} because it is the only
     * place VPN/Tor/I2P/direct are told apart: the aggregate counters cannot say whether a
     * byte went through the tunnel or around it.
     */
    private void logLanes(String phase) {
        long h = handle;
        if (h == 0) {
            Log.i(TAG, "LANES " + phase + " no_handle");
            return;
        }
        try {
            org.json.JSONObject snapshot =
                    new org.json.JSONObject(FoxholeNativeEngine.nativeConnections(h));
            org.json.JSONArray lanes = snapshot.optJSONArray("lanes");
            StringBuilder rendered = new StringBuilder();
            if (lanes != null) {
                for (int i = 0; i < lanes.length(); i++) {
                    org.json.JSONObject lane = lanes.getJSONObject(i);
                    rendered.append(lane.optString("lane"))
                            .append(":up=").append(lane.optLong("bytes_up"))
                            .append(",down=").append(lane.optLong("bytes_down"))
                            .append(",opened=").append(lane.optLong("flows_opened"))
                            .append(",live=").append(lane.optLong("flows_live"))
                            .append(' ');
                }
            }
            org.json.JSONArray connections = snapshot.optJSONArray("connections");
            org.json.JSONArray packages = snapshot.optJSONArray("packages");
            Log.i(TAG, "LANES " + phase
                    + " rows=" + (connections == null ? -1 : connections.length())
                    + " packages=" + (packages == null ? -1 : packages.length())
                    + " omitted=" + snapshot.optLong("omitted_rows")
                    + " dropped_events=" + snapshot.optLong("dropped_events")
                    + " " + rendered.toString().trim());
        } catch (Exception error) {
            Log.e(TAG, "LANES " + phase + " malformed");
        }
    }

    /**
     * Hot policy swap: Tor/I2P gates, per-app rules, kill switch. The TUN stays up and live
     * flows are not torn down, so this is the call that has to prove "the firewall does not
     * stick" — a rule lifted here must apply to the next flow without a restart.
     */
    private void reloadPolicy(String policyPath) throws Exception {
        long h = handle;
        if (h == 0) {
            Log.e(TAG, "POLICY no running engine");
            return;
        }
        String json = readConfig(policyPath);
        long code = FoxholeNativeEngine.nativeReloadPolicy(h, json);
        // A typed code, not an exception: the app has to tell "no Tor in this build" from
        // "the policy is malformed", and a bare IllegalStateException said neither.
        Log.i(TAG, "POLICY result=" + FoxholeNativeEngine.reloadCode(code) + " raw=" + code);
        // And the words beside the code, because one of the eight is general: -1 is a
        // truncated write and a field this schema removed in the same value, and the
        // code alone cannot tell a stand from a bug (docs/17 §31.17).
        if (code < 0) {
            String detail = FoxholeNativeEngine.nativeLastPolicyError(h);
            Log.i(TAG, "POLICY_DETAIL " + (detail == null || detail.isEmpty() ? "<none>" : detail));
        }
        logStats("AFTER_POLICY");
        logLanes("AFTER_POLICY");
    }

    /**
     * Loopback SOCKS5 stub for the I2P lane.
     *
     * <p>This is NOT i2pd and cannot reach a real destination. It exists to exercise the
     * half of the I2P contract the core actually owns: that an `.i2p` name is refused
     * unless DNS is in fake-IP mode, that the route reaches the i2p outbound rather than
     * clearnet, and that the lane fails closed when nothing is listening. Whether an
     * eepsite answers is i2pd's half, and this proves nothing about it.
     *
     * <p>It answers the SOCKS5 handshake and then refuses the CONNECT with 0x04 (host
     * unreachable), which is exactly what an i2pd with no tunnels would say — so a flow
     * that "worked" here would be a core bug, not a pass.
     */
    private void startI2pStub(int port) {
        if (i2pStub != null) {
            Log.i(TAG, "I2P_STUB already listening");
            return;
        }
        try {
            final java.net.ServerSocket server =
                    new java.net.ServerSocket(port, 16, InetAddress.getByName("127.0.0.1"));
            i2pStub = server;
            new Thread(() -> {
                Log.i(TAG, "I2P_STUB listening on 127.0.0.1:" + port);
                while (!server.isClosed()) {
                    try (java.net.Socket client = server.accept()) {
                        i2pStubCalls++;
                        java.io.InputStream in = client.getInputStream();
                        java.io.OutputStream out = client.getOutputStream();
                        int version = in.read();
                        int methods = in.read();
                        for (int i = 0; i < methods && i >= 0; i++) {
                            in.read();
                        }
                        if (version != 5) {
                            continue;
                        }
                        out.write(new byte[] {0x05, 0x00});
                        out.flush();
                        // Read the CONNECT request far enough to be well-formed, then refuse.
                        in.read();
                        in.read();
                        in.read();
                        int type = in.read();
                        int skip = type == 1 ? 4 : type == 3 ? in.read() : 16;
                        for (int i = 0; i < skip; i++) {
                            in.read();
                        }
                        in.read();
                        in.read();
                        out.write(new byte[] {0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
                        out.flush();
                        Log.i(TAG, "I2P_STUB refused a CONNECT (call " + i2pStubCalls + ")");
                    } catch (Throwable t) {
                        if (!server.isClosed()) {
                            Log.i(TAG, "I2P_STUB client error=" + t.getClass().getSimpleName());
                        }
                    }
                }
            }, "foxhole-i2p-stub").start();
        } catch (Throwable t) {
            Log.e(TAG, "I2P_STUB failed to listen=" + t.getClass().getSimpleName());
        }
    }

    private void stopI2pStub() {
        java.net.ServerSocket server = i2pStub;
        i2pStub = null;
        if (server != null) {
            try {
                server.close();
            } catch (Exception ignored) {
            }
            Log.i(TAG, "I2P_STUB stopped calls=" + i2pStubCalls);
        }
    }


    /**
     * Open a real flow to an overlay host — `.i2p` or `.onion` — and report where it went.
     *
     * <p>Resolution succeeding proves only that fake-IP answered. What matters is the flow:
     * it must reach its own lane and fail there when the overlay is unavailable, and it must
     * never appear in the vpn or direct lane — an overlay destination reaching clearnet is
     * the leak this whole gate exists to prevent.
     *
     * <p>The same probe serves both overlays on purpose. The interesting runs are the ones
     * where one overlay is stopped and the other is asked the same question in the same way,
     * and a second probe written separately would be a second thing that could differ.
     */
    private void overlayFetchProbe(String host, String tag, int timeoutSeconds) throws Exception {
        logStats("BEFORE_" + tag);
        logLanes("BEFORE_" + tag);
        long t0 = System.currentTimeMillis();
        String verdict;
        int received = 0;
        // Declared out here because overlay transfers are routinely cut mid-body, and a
        // reply that arrived is evidence whether or not the stream ended tidily. Parsing
        // it only on the clean path threw away the status line of every partial fetch,
        // which read as "nothing came back" for a lane that had just carried 23 KiB.
        java.io.ByteArrayOutputStream head = new java.io.ByteArrayOutputStream();
        try (java.net.Socket s = new java.net.Socket()) {
            // A first contact with a hidden service costs a descriptor fetch and a
            // rendezvous, so the budget has to be a run parameter: too short reads as
            // "the overlay is down" for a destination that was merely slow.
            s.connect(new java.net.InetSocketAddress(host, 80), timeoutSeconds * 1000);
            s.setSoTimeout(timeoutSeconds * 1000);
            // Opening the flow proves the lane accepted it, and that alone leaves the
            // byte counters at zero — which is indistinguishable from a lane nothing
            // ever used. Only a transfer puts bytes on it, and only an eepsite that
            // answers shows the far end was really I2P rather than something that
            // merely accepted a socket on loopback.
            s.getOutputStream().write(("GET / HTTP/1.1\r\nHost: " + host
                    + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            s.getOutputStream().flush();
            java.io.InputStream in = s.getInputStream();
            byte[] buffer = new byte[4096];
            int read;
            while (received < 65536 && (read = in.read(buffer)) > 0) {
                received += read;
                if (head.size() < 200) {
                    head.write(buffer, 0, Math.min(read, 200 - head.size()));
                }
            }
            verdict = received > 0 ? "FETCHED" : "CONNECTED_NO_BYTES";
        } catch (Exception e) {
            // Bytes already on the lane make this a cut transfer, not a refusal. The
            // distinction is the whole point: a refusal means the overlay never carried
            // anything, and saying "refused" after 23 KiB arrived would be a false one.
            verdict = (received > 0 ? "PARTIAL/" : "refused/") + e.getClass().getSimpleName();
        }
        String text = head.toString("UTF-8");
        int eol = text.indexOf('\r');
        String statusLine = text.isEmpty() ? "none" : (eol > 0 ? text.substring(0, eol) : text)
                .trim();
        Log.i(TAG, tag + " host=" + host + " result=" + verdict
                + " bytes=" + received + " status=" + statusLine
                + " ms=" + (System.currentTimeMillis() - t0)
                + " stub_calls=" + i2pStubCalls);
        Thread.sleep(2000);
        logStats("AFTER_" + tag);
        logLanes("AFTER_" + tag);
        logDrain(64);
    }

    /**
     * Continuity: hold a lane blocked across an interruption instead of healing silently.
     *
     * <p>The point of the scenario is the negative half. While a lane is held the traffic
     * must stay blocked — not quietly fall out to `direct`, which would be the leak the
     * whole feature exists to prevent — and only an explicit confirmation resumes it.
     */
    private void continuityScenario(String policyPath, int waitSeconds) throws Exception {
        long h = handle;
        if (h == 0) {
            Log.e(TAG, "CONTINUITY no running engine");
            return;
        }
        if (policyPath != null) {
            reloadPolicy(policyPath);
        }
        Log.i(TAG, "CONTINUITY interrupting via network change");
        netChange();
        long deadline = System.currentTimeMillis() + waitSeconds * 1000L;
        long token = 0;
        while (System.currentTimeMillis() < deadline && token == 0) {
            token = pendingContinuityToken();
            if (token == 0) {
                Thread.sleep(1000);
            }
        }
        Log.i(TAG, "CONTINUITY token_present=" + (token != 0));
        if (token == 0) {
            Log.i(TAG, "CONTINUITY no hold was raised; nothing to confirm");
            logStats("CONTINUITY_NO_HOLD");
            return;
        }
        // Held means blocked, and it has to be tested on a *new* flow. HttpURLConnection
        // keeps a connection pool, so an exit probe during the hold can be answered by a
        // socket opened before it — which looks exactly like a lane that leaked.
        String heldExit = freshFlowProbe("continuity_held");
        logStats("CONTINUITY_HELD");
        logLanes("CONTINUITY_HELD");

        int stale = FoxholeNativeEngine.nativeConfirmContinuity(h, token + 1);
        Log.i(TAG, "CONTINUITY stale_token_result=" + stale
                + " (2 = correctly refused)");

        int confirmed = FoxholeNativeEngine.nativeConfirmContinuity(h, token);
        Log.i(TAG, "CONTINUITY confirm_result=" + confirmed + " (0 = confirmed)");
        Thread.sleep(6000);
        String resumedExit = freshFlowProbe("continuity_resumed");
        logStats("CONTINUITY_RESUMED");
        Log.i(TAG, "CONTINUITY held_exit=" + heldExit + " resumed_exit=" + resumedExit);
    }


    /**
     * A brand-new TCP flow to a public host, with no connection pool in the way.
     *
     * <p>This is the only honest way to ask "is the lane blocked right now": every pooled
     * HTTP client will happily answer from a socket that was opened before the block.
     */
    private String freshFlowProbe(String label) {
        long t0 = System.currentTimeMillis();
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress("example.com", 80), 12000);
            s.getOutputStream().write(
                    "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().flush();
            int first = s.getInputStream().read();
            String verdict = first < 0 ? "EOF" : "ANSWERED";
            Log.i(TAG, "FRESH_FLOW label=" + label + " result=" + verdict
                    + " ms=" + (System.currentTimeMillis() - t0));
            return verdict;
        } catch (Exception e) {
            Log.i(TAG, "FRESH_FLOW label=" + label + " result=BLOCKED/"
                    + e.getClass().getSimpleName() + " ms=" + (System.currentTimeMillis() - t0));
            return "BLOCKED";
        }
    }

    /** The token the engine is waiting on, or 0. */
    private long pendingContinuityToken() {
        long h = handle;
        if (h == 0) {
            return 0;
        }
        try {
            org.json.JSONObject stats =
                    new org.json.JSONObject(FoxholeNativeEngine.nativeStats(h));
            org.json.JSONObject continuity = stats.optJSONObject("continuity");
            if (continuity == null) {
                return 0;
            }
            Log.i(TAG, "CONTINUITY state=" + continuity);
            return continuity.optLong("pending_token", 0);
        } catch (Exception error) {
            return 0;
        }
    }

    /**
     * Arm the kill switch in the middle of a live download.
     *
     * <p>A download that finishes anyway means the switch only reached new flows, which is
     * the failure this scenario exists to catch: "everything is off" has to be true of the
     * transfer already running, not just the next one.
     */
    private void killSwitchDuringDownload(String policyPath, String url) throws Exception {
        long h = handle;
        if (h == 0) {
            Log.e(TAG, "KILLDL no running engine");
            return;
        }
        final long[] read = {0};
        final String[] verdict = {"running"};
        Thread download = new Thread(() -> {
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
                c.setConnectTimeout(20000);
                c.setReadTimeout(60000);
                java.io.InputStream in = c.getInputStream();
                byte[] buffer = new byte[8192];
                while (true) {
                    int n = in.read(buffer);
                    if (n < 0) {
                        verdict[0] = "completed";
                        break;
                    }
                    read[0] += n;
                }
                in.close();
            } catch (Exception e) {
                verdict[0] = "died/" + e.getClass().getSimpleName();
            }
        }, "foxhole-killdl");
        download.start();
        Thread.sleep(3000);
        long before = read[0];
        Log.i(TAG, "KILLDL bytes_before_switch=" + before);
        reloadPolicy(policyPath);
        download.join(45000);
        Log.i(TAG, "KILLDL verdict=" + verdict[0]
                + " bytes_before=" + before + " bytes_total=" + read[0]
                + " grew_after_switch=" + (read[0] - before));
        logStats("AFTER_KILLDL");
        logLanes("AFTER_KILLDL");
    }

    /**
     * One large upload through the tunnel, offered in one flow.
     *
     * <p>BASELINES §3a killed three of three of these on an unimpaired link: the
     * backlog ceiling was a volume verdict, the TUN side delivers at memory speed
     * and any real socket does not, so an ordinary upload tripped it in under a
     * second and died between 0.4 and 1.4 MiB. The rule is now time without
     * progress and the volume ceiling applies backpressure instead, so the
     * question this asks is simply whether the whole body arrives.
     *
     * <p>The verdict is not the HTTP status on its own — a proxy can answer 200
     * having read less than was offered. It is offered == written together with
     * `flow_backlogs_exceeded` staying where it started.
     */
    private void upload(int mib, String url) throws Exception {
        long offered = (long) mib * 1024L * 1024L;
        logStats("BEFORE_UPLOAD");
        long backlogsBefore = statValue("flow_backlogs_exceeded");
        long upBefore = statValue("bytes_up");
        long written = 0;
        String verdict;
        int status = -1;
        long t0 = System.currentTimeMillis();
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.setConnectTimeout(20000);
            c.setReadTimeout(180000);
            // Fixed-length, not chunked: the length is in the request header, so a
            // short body is a protocol error at the far end rather than a truncation
            // that still reads as a clean 200.
            c.setFixedLengthStreamingMode(offered);
            c.setRequestProperty("Content-Type", "application/octet-stream");
            java.io.OutputStream out = c.getOutputStream();
            byte[] chunk = new byte[64 * 1024];
            java.util.Arrays.fill(chunk, (byte) 0x5a);
            while (written < offered) {
                int n = (int) Math.min(chunk.length, offered - written);
                out.write(chunk, 0, n);
                written += n;
                if (written % (4L * 1024 * 1024) == 0) {
                    Log.i(TAG, "UPLOAD progress mib=" + (written / 1048576)
                            + " ms=" + (System.currentTimeMillis() - t0));
                }
            }
            out.flush();
            out.close();
            status = c.getResponseCode();
            c.getInputStream().close();
            verdict = "completed";
        } catch (Exception e) {
            verdict = "died/" + e.getClass().getSimpleName() + ":" + e.getMessage();
        }
        long ms = System.currentTimeMillis() - t0;
        Thread.sleep(2000);
        long backlogsAfter = statValue("flow_backlogs_exceeded");
        long upAfter = statValue("bytes_up");
        Log.i(TAG, "UPLOAD verdict=" + verdict
                + " offered=" + offered + " written=" + written
                + " complete=" + (written == offered)
                + " http=" + status + " ms=" + ms
                + " kbps=" + (ms > 0 ? (written * 8L / ms) : 0)
                + " backlogs_delta=" + (backlogsAfter - backlogsBefore)
                + " bytes_up_delta=" + (upAfter - upBefore));
        logStats("AFTER_UPLOAD");
        logLanes("AFTER_UPLOAD");
        logDrain(64);
    }

    /**
     * A push channel: one flow that goes quiet for longer than the old timeout and
     * then has to still be there.
     *
     * <p>`idle_timeout_s` used to reach TCP as well at 300 s, which is shorter than
     * every push channel there is — the connection died, nothing named the
     * application, and it was indistinguishable from the network's fault.
     * `tcp_idle_timeout_s` now defaults to an hour.
     *
     * <p>IMAP on 143 is the sink because the protocol itself guarantees the far
     * end will not hang up first: RFC 3501 says a server MUST NOT auto-logout an
     * authenticated-or-not connection in under 30 minutes. So a connection that
     * dies at six minutes died on this side of the wire, which is the whole
     * question.
     */
    private void pushChannel(String host, int port, int idleSeconds) throws Exception {
        logStats("BEFORE_PUSH");
        long idleBefore = statValue("flow_idle_timeouts");
        String verdict;
        String banner = "";
        String afterIdle = "";
        long t0 = System.currentTimeMillis();
        java.net.Socket socket = new java.net.Socket();
        try {
            socket.connect(new java.net.InetSocketAddress(host, port), 20000);
            // Platform keepalive on, as a real push client would have it. It costs
            // nothing here and it is the shape being claimed to survive.
            socket.setKeepAlive(true);
            socket.setSoTimeout(60000);
            BufferedReader reader = new BufferedReader(
                    new java.io.InputStreamReader(socket.getInputStream()));
            java.io.OutputStream out = socket.getOutputStream();
            banner = String.valueOf(reader.readLine());
            Log.i(TAG, "PUSH banner=" + (banner.length() > 60
                    ? banner.substring(0, 60) : banner));
            Log.i(TAG, "PUSH going silent for " + idleSeconds + "s");
            long slept = 0;
            while (slept < idleSeconds) {
                Thread.sleep(30000);
                slept += 30;
                Log.i(TAG, "PUSH silent=" + slept + "s socket_closed=" + socket.isClosed()
                        + " connected=" + socket.isConnected());
            }
            // The only traffic in the whole window, and the proof: if the core
            // reclaimed the flow, this write or this read fails.
            out.write("a1 NOOP\r\n".getBytes("US-ASCII"));
            out.flush();
            afterIdle = String.valueOf(reader.readLine());
            // Any reply at all is the proof. What the server chose to say back is
            // its business — the claim under test is that the flow was still
            // there to carry it, and a torn-down flow cannot produce a line.
            verdict = afterIdle.isEmpty() || "null".equals(afterIdle)
                    ? "died/silent_after_idle" : "survived";
        } catch (Exception e) {
            verdict = "died/" + e.getClass().getSimpleName() + ":" + e.getMessage();
        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
                // Closing the probe socket cannot change the verdict already recorded.
            }
        }
        long idleAfter = statValue("flow_idle_timeouts");
        Log.i(TAG, "PUSH verdict=" + verdict
                + " idle_s=" + idleSeconds
                + " total_ms=" + (System.currentTimeMillis() - t0)
                + " reply_after_idle=" + afterIdle
                + " idle_timeouts_delta=" + (idleAfter - idleBefore));
        logStats("AFTER_PUSH");
        logLanes("AFTER_PUSH");
    }

    /** One counter out of the live snapshot, for scenarios that need a before/after delta. */
    private long statValue(String key) {
        long h = handle;
        if (h == 0) {
            return -1;
        }
        try {
            return new org.json.JSONObject(FoxholeNativeEngine.nativeStats(h)).optLong(key);
        } catch (Exception error) {
            return -1;
        }
    }

    /**
     * A UDP query to a resolver through a TCP-only outbound.
     *
     * <p>The refusal is correct; what is being checked is that it is *counted* and
     * journalled once, rather than being a silent nothing.
     */
    private void naiveUdpProbe() throws Exception {
        logStats("BEFORE_UDP_REFUSAL");
        try (java.net.DatagramSocket sock = new java.net.DatagramSocket()) {
            sock.setSoTimeout(3000);
            // NTP, not DNS: port 53 is taken by the interceptor, which answers it from
            // its own upstream, so a query there never reaches the outbound at all and
            // proves nothing about how a TCP-only protocol refuses a datagram.
            byte[] query = new byte[48];
            query[0] = 0x1b;
            sock.send(new java.net.DatagramPacket(
                    query, query.length, InetAddress.getByName("216.239.35.0"), 123));
            try {
                sock.receive(new java.net.DatagramPacket(new byte[512], 512));
                Log.i(TAG, "UDP_REFUSAL got a reply (unexpected for a TCP-only outbound)");
            } catch (Exception expected) {
                Log.i(TAG, "UDP_REFUSAL no reply, as designed");
            }
        }
        Thread.sleep(2000);
        logStats("AFTER_UDP_REFUSAL");
        logDrain(64);
    }

    /**
     * The long comparative run. Samples counters, lanes and footprint on a fixed cadence and
     * re-checks the exit on every sample, so a tunnel that dies quietly forty minutes in is
     * visible as the sample where the fingerprint changed rather than as a final total that
     * still looks plausible.
     */
    private void soak(String cfgPath, boolean withNetwork, int minutes, int intervalSeconds)
            throws Exception {
        if (minutes <= 0) {
            minutes = 30;
        }
        if (intervalSeconds <= 0) {
            intervalSeconds = 60;
        }
        if (!stopEngine()) {
            Log.e(TAG, "SOAK previous_stop_incomplete");
            return;
        }
        Log.i(TAG, "SOAK begin minutes=" + minutes + " interval_s=" + intervalSeconds
                + " " + processFootprint());
        handle = startEngine(cfgPath, withNetwork);
        if (handle == 0) {
            Log.e(TAG, "SOAK start_failed");
            return;
        }
        Thread.sleep(3000);
        dnsProbes();
        String first = exitIpProbes("soak_first");
        logStats("SOAK_0");
        logLanes("SOAK_0");

        long deadline = System.currentTimeMillis() + minutes * 60_000L;
        int sample = 0;
        int exitMatches = 0;
        int exitChecks = 0;
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(intervalSeconds * 1000L);
            sample++;
            logStats("SOAK_" + sample);
            logLanes("SOAK_" + sample);
            Log.i(TAG, "SOAK sample=" + sample + " " + processFootprint());
            logDrain(128);
            String now = exitIpProbes("soak_" + sample);
            exitChecks++;
            if (now.equals(first)) {
                exitMatches++;
            } else {
                Log.w(TAG, "SOAK sample=" + sample + " exit_changed");
            }
        }
        logStats("SOAK_END");
        logLanes("SOAK_END");
        Log.i(TAG, "SOAK end samples=" + sample
                + " exit_stable=" + exitMatches + "/" + exitChecks
                + " protect_calls=" + protectCalls + " protect_ok=" + protectOk
                + " " + processFootprint());
        stopEngine();
        Thread.sleep(2000);
        Log.i(TAG, "SOAK post_stop " + processFootprint());
    }

    private void netChange() {
        if (handle == 0) {
            Log.e(TAG, "NETCHANGE no running engine");
            return;
        }
        Network underlying = activeNetwork();
        long nh = underlying == null ? 0 : underlying.getNetworkHandle();
        boolean underlyingAccepted = underlying != null
                && setUnderlyingNetworks(new Network[] {underlying});
        FoxholeNativeEngine.nativeNetworkChangedWithHandle(handle, nh);
        Log.i(TAG, "NETCHANGE delivered handle_present=" + (nh != 0)
                + " underlying_accepted=" + underlyingAccepted);
        logStats("AFTER_NETCHANGE");
    }

    private void startMonitor(int drainMax) {
        monitorRun = true;
        new Thread(() -> {
            while (monitorRun && handle != 0) {
                try {
                    Thread.sleep(5000);
                    logStats("MON");
                    logDrain(drainMax);
                } catch (Throwable t) {
                    return;
                }
            }
        }, "foxhole-test-monitor").start();
    }

    private void stopMonitor() {
        monitorRun = false;
    }

    private void logStats(String phase) {
        long h = handle;
        if (h == 0) {
            Log.i(TAG, "STATS " + phase + " no_handle");
            return;
        }
        try {
            org.json.JSONObject stats =
                    new org.json.JSONObject(FoxholeNativeEngine.nativeStats(h));
            // generation/policy_revision/reconnects are the three numbers that say whether
            // the engine quietly rebuilt itself under a long run. Without them a soak can
            // only report that the totals look plausible at the end.
            org.json.JSONArray selectors = stats.optJSONArray("selectors");
            StringBuilder active = new StringBuilder();
            if (selectors != null) {
                for (int i = 0; i < selectors.length(); i++) {
                    active.append(selectors.getJSONObject(i).optString("tag"))
                            .append('=')
                            .append(selectors.getJSONObject(i).optString("active"))
                            .append(' ');
                }
            }
            Log.i(TAG, "STATS " + phase
                    + " gen=" + stats.optLong("generation")
                    + " rev=" + stats.optLong("policy_revision")
                    + " reconnects=" + stats.optLong("reconnects")
                    + (active.length() == 0 ? "" : " selector=" + active.toString().trim())
                    + " connected=" + stats.optBoolean("connected")
                    + " up=" + stats.optLong("bytes_up")
                    + " down=" + stats.optLong("bytes_down")
                    + " active=" + stats.optLong("active_flows")
                    + " rejected=" + stats.optLong("rejected_flows")
                    + " blocked=" + stats.optLong("blocked_flows")
                    + " dns=" + stats.optLong("dns_queries")
                    + " dns_blocked=" + stats.optLong("dns_blocked")
                    // D14's evidence, and it reads both ways. Non-zero means the device
                    // tried encrypted DNS straight at our advertised resolver and was
                    // sent back to the port the interceptor reads. Zero on a real_ip
                    // profile with a blocklist and Private DNS on "Automatic" means the
                    // probe never reached us — which is the state where every domain
                    // rule silently does nothing.
                    + " dns_enc_bypass=" + stats.optLong("dns_encrypted_bypass")
                    // A correct refusal that nothing counted was D7: the datagram is
                    // refused by design, and the counter is the only evidence it happened.
                    + " udp_unsupported=" + stats.optLong("udp_unsupported")
                    // The one pair that separates "the L3 tunnel is broken" from "the L3
                    // tunnel is fine": rising untranslated counters with flat bytes_up is
                    // D10 alive, and the event says which trigger.
                    + " untrans_up=" + stats.optLong("tunnel_untranslated_up")
                    + " untrans_down=" + stats.optLong("tunnel_untranslated_down")
                    // The three numbers that finish the D10 diagnosis. split_to_stack must
                    // equal the DNS query count and nothing else; tunnel_unsealed must stop
                    // growing once the handshake is done; tunnel_socket_errors must be zero.
                    // All three clean with TCP still dead means the packet reached the wire
                    // and the cause is the peer, allowed_ips or the far-side MTU.
                    + " split_stack=" + stats.optLong("split_to_stack")
                    + " unsealed=" + stats.optLong("tunnel_unsealed")
                    + " sock_err=" + stats.optLong("tunnel_socket_errors")
                    + " dial_errors=" + stats.optLong("dial_errors")
                    + " flow_errors=" + stats.optLong("flow_errors")
                    // Roaming on a packet tunnel is invisible from outside without these:
                    // the peer state machine keeps producing handshakes on a socket bound
                    // to a dead interface, so every counter above keeps moving while no
                    // user packet arrives. rebinds is the only evidence the socket was
                    // recreated; offline_packets says the relay refused to carry traffic
                    // rather than putting it on the wire unprotected.
                    + " rebinds=" + stats.optLong("tunnel_rebinds")
                    + " rebind_fail=" + stats.optLong("tunnel_rebind_failures")
                    + " offline_pkts=" + stats.optLong("tunnel_offline_packets")
                    // D15. The run that found it had every counter above reading zero
                    // while a core burned and bytes_up invented gigabytes, so "all clean"
                    // meant nothing. These four are the ones that would have spoken:
                    // routing_loops says our own output came back through the tun,
                    // recv_errors says the receive arm is spinning on an error it used to
                    // discard, queue_dropped says the peer state machine is throwing the
                    // user's packets away, peer_silences says the far side answered
                    // nothing while we were sending. On a healthy tunnel all four are 0.
                    + " routing_loops=" + stats.optLong("tunnel_routing_loops")
                    + " recv_errors=" + stats.optLong("tunnel_receive_errors")
                    + " queue_dropped=" + stats.optLong("tunnel_queue_dropped")
                    + " peer_silences=" + stats.optLong("tunnel_peer_silences")
                    // The backlog rule is now time-without-progress, not volume, and the
                    // volume ceiling became backpressure. A 32 MiB upload that used to
                    // die at 0.4-1.4 MiB is the reason this is on the standard line.
                    + " backlogs=" + stats.optLong("flow_backlogs_exceeded")
                    + " idle_timeouts=" + stats.optLong("flow_idle_timeouts"));
        } catch (Exception error) {
            Log.e(TAG, "STATS " + phase + " malformed");
        }
    }

    private void logDrain(int max) {
        long h = handle;
        if (h == 0) {
            Log.i(TAG, "EVENTS no_handle");
            return;
        }
        try {
            org.json.JSONObject batch =
                    new org.json.JSONObject(FoxholeNativeEngine.nativeDrainEvents(h, max));
            org.json.JSONArray events = batch.getJSONArray("events");
            Map<String, Integer> kinds = new TreeMap<>();
            for (int index = 0; index < events.length(); index++) {
                String kind = events.getJSONObject(index).optString("type", "unknown");
                kinds.put(kind, kinds.getOrDefault(kind, 0) + 1);
            }
            // Reasons, not just kinds: "blocked=1" cannot say whether the packet was
            // refused for the address or for the family, and those are different bugs.
            StringBuilder reasons = new StringBuilder();
            for (int index = 0; index < events.length(); index++) {
                org.json.JSONObject event = events.getJSONObject(index);
                String reason = event.optString("reason", "");
                if (!reason.isEmpty()) {
                    reasons.append(event.optString("type", "?")).append(':').append(reason)
                            .append(' ');
                }
            }
            if (reasons.length() > 0) {
                Log.i(TAG, "EVENT_REASONS " + reasons.toString().trim());
            }
            // The whole record for a tunnel refusal: the destination and transport say
            // which family and which flow, and that is what separates "IPv6 reached a
            // v4-only tunnel" from "a v4 packet arrived with a source we do not own".
            for (int index = 0; index < events.length(); index++) {
                org.json.JSONObject event = events.getJSONObject(index);
                String reason = event.optString("reason", "");
                if (reason.startsWith("tunnel_")) {
                    Log.i(TAG, "TUNNEL_REFUSAL " + event);
                }
            }
            // Continuity and lane-availability events carry their verdict in a field
            // rather than in `reason`, so the kind histogram above cannot show it. What
            // an expired deadline *did* is the whole question these events answer:
            // `keep_blocking` and `stop_engine_leaving_network_open` are the difference
            // between a held tunnel and traffic on the open network (docs/17 §29.10).
            for (int index = 0; index < events.length(); index++) {
                org.json.JSONObject event = events.getJSONObject(index);
                String kind = event.optString("type", "");
                if (kind.contains("confirmation") || kind.contains("outbound")
                        || kind.contains("lane")) {
                    Log.i(TAG, "CONTINUITY_EVENT " + event);
                }
            }
            Log.i(TAG, "EVENTS count=" + events.length()
                    + " dropped=" + batch.optLong("dropped")
                    + " kinds=" + kinds);
        } catch (Exception error) {
            Log.e(TAG, "EVENTS malformed");
        }
    }

    /** Blocklist proof: blocked names must fail to resolve, a control name must succeed. */
    private void dnsProbes() {
        resolveProbe(DNS_BLOCKED_SUFFIX, true);
        resolveProbe(DNS_BLOCKED_EXACT, true);
        resolveProbe(DNS_ALLOWED, false);
    }

    private void resolveProbe(String host, boolean expectBlocked) {
        long t0 = System.currentTimeMillis();
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            long dt = System.currentTimeMillis() - t0;
            int v4 = 0;
            int v6 = 0;
            for (InetAddress a : addrs) {
                if (a instanceof java.net.Inet6Address) {
                    v6++;
                } else {
                    v4++;
                }
            }
            // The families matter more than the count: an AAAA answer on a v4-only
            // tunnel is what sends the SYN somewhere the tunnel cannot carry.
            Log.i(TAG, "DNS host=" + host + " expect_blocked=" + expectBlocked
                    + " result=RESOLVED count=" + addrs.length
                    + " v4=" + v4 + " v6=" + v6 + " ms=" + dt);
        } catch (Exception e) {
            long dt = System.currentTimeMillis() - t0;
            Log.i(TAG, "DNS host=" + host + " expect_blocked=" + expectBlocked
                    + " result=FAILED/" + e.getClass().getSimpleName() + " ms=" + dt);
        }
    }

    /**
     * Ask every echo service where this request came from, and log a fingerprint of the
     * answer rather than the answer.
     *
     * <p>The fingerprint is what makes the result usable: two runs can be compared for
     * "same exit" or "different exit" without the owner's home address or their server's
     * address ever reaching a log, a report or a screenshot. Returns the fingerprints
     * joined so a caller can compare a tunnelled run against the baseline.
     */
    private String exitIpProbes(String phase) {
        StringBuilder joined = new StringBuilder();
        for (String[] echo : EXIT_ECHOES) {
            String fingerprint = exitIpProbe(phase + "_" + echo[0], echo[1]);
            if (joined.length() > 0) {
                joined.append('/');
            }
            joined.append(fingerprint);
        }
        String all = joined.toString();
        Log.i(TAG, "EXIT_SET phase=" + phase + " fingerprints=" + all);
        return all;
    }

    private String exitIpProbe(String label, String url) {
        long t0 = System.currentTimeMillis();
        try {
            HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(20000);
            c.setReadTimeout(20000);
            BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
            String body = r.readLine();
            r.close();
            boolean plausible = body != null
                    && body.length() >= 2
                    && body.length() <= 64
                    && body.matches("[0-9a-fA-F:.]+");
            String fingerprint = plausible ? fingerprint(body.trim()) : "none";
            Log.i(TAG, "EXIT_PROBE label=" + label
                    + " status=" + c.getResponseCode()
                    + " plausible_ip=" + plausible
                    + " ip_fp=" + fingerprint
                    + " ms=" + (System.currentTimeMillis() - t0));
            return fingerprint;
        } catch (Exception e) {
            Log.e(TAG, "EXIT_PROBE label=" + label
                    + " failed=" + e.getClass().getSimpleName()
                    + " ms=" + (System.currentTimeMillis() - t0));
            return "fail";
        }
    }

    /** First 6 hex digits of SHA-256. Enough to compare two exits, useless for finding one. */
    private static String fingerprint(String value) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 3; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (Exception e) {
            return "err";
        }
    }

    private boolean stopEngine() {
        stopMonitor();
        long h = handle;
        if (h != 0) {
            int result = FoxholeNativeEngine.nativeStop(h);
            if (result == FoxholeNativeEngine.STOP_TIMED_OUT) {
                Log.w(TAG, "STOP timed_out handle_retained=true");
                return false;
            }
            if (result == FoxholeNativeEngine.STOP_PANICKED) {
                Log.e(TAG, "STOP panicked handle_retained=true");
                return false;
            }
            handle = 0;
            Log.i(TAG, "STOP result=" + result);
        }
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
            }
            tun = null;
        }
        return true;
    }

    @Override
    public void onDestroy() {
        stopEngine();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.w(TAG, "VPN permission revoked");
        stopEngine();
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
        super.onRevoke();
    }
}
