package com.foxhole.core.runtime;

/**
 * JNI facade for libfoxhole_native.so — the experimental Rust client core.
 *
 * Package/class name must stay in sync with the exported symbols
 * (Java_com_foxhole_core_runtime_FoxholeNativeEngine_*). In the real app this is what
 * {@code FoxCoreRuntime : FoxholeRuntime} calls directly.
 */
public final class FoxholeNativeEngine {
    public static final int STOPPED = 0;
    public static final int ALREADY_STOPPED = 1;
    public static final int STOP_TIMED_OUT = 2;
    public static final int STOP_UNKNOWN_HANDLE = 3;
    public static final int STOP_PANICKED = -1;

    public static final int CONTINUITY_CONFIRMED = 0;
    public static final int CONTINUITY_NOTHING_PENDING = 1;
    public static final int CONTINUITY_STALE_TOKEN = 2;
    public static final int CONTINUITY_UNKNOWN_HANDLE = 3;

    /** Typed refusals from {@link #nativeReloadPolicy}; a positive value is the revision. */
    public static final int RELOAD_INVALID = -1;
    public static final int RELOAD_UNKNOWN_OUTBOUND = -2;
    public static final int RELOAD_TOR_UNAVAILABLE = -3;
    public static final int RELOAD_I2P_UNAVAILABLE = -4;
    public static final int RELOAD_OVERLAY_WITHOUT_FAKE_IP = -5;
    public static final int RELOAD_NO_ATTRIBUTION = -6;
    public static final int RELOAD_REVISION_CONFLICT = -7;
    public static final int RELOAD_PACKET_TUNNEL_REJECTS_FAKE_IP = -8;

    public static String reloadCode(long value) {
        if (value > 0) {
            return "revision=" + value;
        }
        switch ((int) value) {
            case 0: return "not_running";
            case RELOAD_INVALID: return "invalid_policy";
            case RELOAD_UNKNOWN_OUTBOUND: return "unknown_outbound";
            case RELOAD_TOR_UNAVAILABLE: return "tor_unavailable";
            case RELOAD_I2P_UNAVAILABLE: return "i2p_unavailable";
            case RELOAD_OVERLAY_WITHOUT_FAKE_IP: return "overlay_without_fake_ip";
            case RELOAD_NO_ATTRIBUTION: return "no_attribution";
            case RELOAD_REVISION_CONFLICT: return "revision_conflict";
            case RELOAD_PACKET_TUNNEL_REJECTS_FAKE_IP: return "packet_tunnel_rejects_fake_ip";
            default: return "unknown_code=" + value;
        }
    }

    static {
        System.loadLibrary("foxhole_native");
    }

    /** Core version string. */
    public static native String nativeVersion();

    /** Core ABI version integer. */
    public static native int nativeAbiVersion();

    /** Versioned capabilities document as JSON. */
    public static native String nativeCapabilities();

    /**
     * Start the tunnel over an already-established TUN fd.
     *
     * @param tunFd      detached TUN fd (native takes ownership for the session)
     * @param configJson typed EngineConfig JSON
     * @param host       object exposing {@code boolean protectSocket(int)}
     * @return opaque handle, or 0 on failure
     */
    public static native long nativeStart(int tunFd, String configJson, Object host);

    /**
     * Production bootstrap ABI: like {@link #nativeStart} but pins outbound sockets and
     * bootstrap DNS to a specific Android {@code Network.getNetworkHandle()}.
     */
    public static native long nativeStartWithNetwork(
            int tunFd, String configJson, long networkHandle, Object host);

    /**
     * Production bootstrap with a signed DNS rule set installed before the first query.
     *
     * <p>The pinned public key and minimum sequence live in {@code configJson}; update bytes
     * cannot choose their own trust root.
     */
    public static native long nativeStartWithNetworkAndDnsRuleSet(
            int tunFd,
            String configJson,
            long networkHandle,
            String name,
            byte[] manifest,
            byte[] signature,
            byte[] artifact,
            Object host);

    /**
     * Production bootstrap with a DNS rule set trusted by the signed APK.
     *
     * <p>This entry point is only for immutable bytes packaged with the application. Downloaded
     * updates must use {@link #nativeInstallDnsRuleSet} and pass signature, freshness, and rollback
     * verification.
     */
    public static native long nativeStartWithNetworkAndTrustedDnsRuleSet(
            int tunFd,
            String configJson,
            long networkHandle,
            String name,
            byte[] artifact,
            Object host);

    /**
     * Verify and atomically activate a signed DNS rule-set update.
     *
     * <p>Returns the policy revision. A rejected update leaves the previous verified rule set
     * active.
     */
    public static native long nativeInstallDnsRuleSet(
            long handle,
            String name,
            byte[] manifest,
            byte[] signature,
            byte[] artifact);

    /**
     * Request a stop and join the data-plane worker.
     *
     * <p>A timeout deliberately keeps the native handle valid so the caller can retry; a new
     * Android worker cannot start over it.
     */
    public static native int nativeStop(long handle);

    /** Counters snapshot as JSON, including dns_queries/dns_blocked/dns_allowed. */
    public static native String nativeStats(long handle);

    /**
     * Live flows and per-app traffic totals as JSON.
     *
     * <p>Proportional to the number of open flows, so it is a separate call from {@link
     * #nativeStats}. While the VPN is up this is the only source of per-app numbers: Android's
     * own {@code NetworkStats} attributes tunnelled bytes to the tun interface, not to the app.
     */
    public static native String nativeConnections(long handle);

    /**
     * Take the audit events produced since the previous call.
     *
     * <p>Returns {@code {"events":[...],"dropped":N}}. A non-zero {@code dropped} means this
     * reader was too slow and the bounded queue discarded records — the data plane never waits
     * for it, so the batch is not a complete account of what happened.
     */
    public static native String nativeDrainEvents(long handle, int max);

    /** Atomically replace route/DNS/traffic policy. Returns the installed revision. */
    public static native long nativeReloadPolicy(long handle, String policyJson);

    /**
     * Why the most recent reload was refused, in words. Empty when the last one was
     * applied, when none was attempted, or when the handle is not running.
     *
     * <p>Read after a negative {@link #nativeReloadPolicy}, and only for the detail —
     * the code is what the app switches on. It exists because {@link #RELOAD_INVALID}
     * alone cannot be acted on: the other seven refusals each name their cause, while
     * -1 covers a truncated write and a field this schema removed in the same value,
     * and those need different fixes.
     */
    public static native String nativeLastPolicyError(long handle);

    /**
     * Drop the engine without waiting for the worker, not even the stop timeout.
     *
     * <p>Returns the same codes as {@link #nativeStop}. A wedged worker goes to the
     * process-wide quarantine, so this buys a return from the call, not a free descriptor.
     */
    public static native int nativeForceKill(long handle);

    /**
     * Release the lanes a continuity hold suspended, at the cost of a reconnect.
     *
     * <p>{@code token} is the one carried by the {@code confirmation_required} event.
     * Returns 0 confirmed, 1 nothing pending, 2 stale token, 3 unknown handle, -1 panic.
     */
    public static native int nativeConfirmContinuity(long handle, long token);

    /** Legacy network-change callback: forces stateful outbounds to reconnect. */
    public static native void nativeNetworkChanged(long handle);

    /** Network-change callback carrying the new {@code Network.getNetworkHandle()}. */
    public static native void nativeNetworkChangedWithHandle(long handle, long networkHandle);

    private FoxholeNativeEngine() {
    }
}
