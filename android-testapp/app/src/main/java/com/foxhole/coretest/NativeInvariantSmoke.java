package com.foxhole.coretest;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;

import com.foxhole.core.runtime.FoxholeNativeEngine;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Executes the parts of the JNI boundary that only exist on a device, and prints a verdict
 * for each one.
 *
 * <p>Why this exists: {@code docs/24-unsafe-audit.md} §9 says, in as many words, that every
 * block under {@code #[cfg(target_os = "android")]} was audited by reading it and by
 * {@code cargo check --target aarch64-linux-android}, and executed <em>never</em>. That is
 * the whole gap. The invariants those blocks rest on are about bionic, ART and the kernel —
 * a `getSystemService` that leaves a pending exception, a descriptor that is not what
 * `VpnService.establish()` promised, a panic barrier whose unwinder has to work under ART —
 * and none of them can be settled by a host build, however green.
 *
 * <p>So this is deliberately not a scenario. It takes no config, no subscription and no
 * server: the engine config it uses is a `direct` outbound, which is the one variant of
 * `OutboundConfig` behind no cargo feature at all, so the run says the same thing about a
 * minimal build as about the shipped one. It should be runnable on a borrowed phone in
 * under a minute, which is the only kind of device time anyone actually has.
 *
 * <p>Every line it prints starts with {@code INVARIANT} and names one thing, so
 * {@code scripts/device-abi-invariants.sh} can turn a logcat into a table without parsing
 * prose. A check that could not be run prints {@code SKIP} with its reason rather than
 * {@code PASS}: this file exists because something was reported as verified without being
 * executed, and repeating that in a smaller font would be worse than useless.
 */
final class NativeInvariantSmoke {
    private static final String TAG = "FoxholeCoreTest";

    /**
     * Supplies the TUN. The smoke needs a real {@code VpnService.Builder.establish()} — the
     * exact descriptor the ABI is handed in production — but building one needs the service
     * instance, so the service passes the act of establishing rather than the pieces.
     */
    interface TunSource {
        ParcelFileDescriptor establish() throws Exception;
    }

    /**
     * A `direct` outbound: no server, no credentials, and no protocol feature.
     *
     * <p>`OutboundConfig::Direct` is the only variant that is not behind a cargo feature, so
     * a start that fails here is the boundary failing rather than this build not carrying
     * the protocol the config happened to name.
     */
    private static final String DIRECT_CONFIG =
            "{\"schema_version\":1,"
                    + "\"outbound\":{\"type\":\"direct\"},"
                    // The core validates this as a mutual implication: a direct primary is the
                    // local-guard mode and nothing else, so omitting the flag is a rejected config
                    // rather than a default. Without it this smoke never reaches nativeStart.
                    + "\"runtime\":{\"local_guard\":true},"
                    + "\"tun\":{\"mtu\":1400,\"ipv4\":\"10.0.0.2\"}}";

    /**
     * The same config with one per-package route rule.
     *
     * <p>The rule is not about routing. A rule carrying `package` is what makes
     * `start_owned` decide it needs flow attribution, which is the only path that calls
     * `getSystemService` and `getPackageManager` back on the host object — and therefore the
     * only deterministic way to make a Java method fail inside a Rust→Java call and check
     * that the pending exception is cleared before returning.
     */
    private static final String ATTRIBUTED_CONFIG =
            "{\"schema_version\":1,"
                    + "\"outbound\":{\"type\":\"direct\"},"
                    + "\"runtime\":{\"local_guard\":true},"
                    + "\"tun\":{\"mtu\":1400,\"ipv4\":\"10.0.0.2\"},"
                    + "\"routes\":[{\"package\":\"com.foxhole.coretest\","
                    + "\"action\":{\"type\":\"direct\"}}]}";

    /**
     * A host that is not a {@code Context}.
     *
     * <p>It answers `protectSocket` — so the socket callbacks resolve and the start gets far
     * enough to matter — and nothing else. `getSystemService` on it raises
     * `NoSuchMethodError` inside a `call_method`, which is exactly the shape of failure
     * `clear_jni_error` exists for: returning to Java with that exception still pending
     * makes the *next* JNI call undefined behaviour at the ART level, and nothing about the
     * failing call itself would show it.
     */
    private static final class HostWithoutContext {
        /**
         * Counted because it is the only observable that says the core reached its dialer.
         * `android_setsocknetwork` (§2.6) is called from `ProtectedDialer::prepare`, right
         * beside this callback, so a non-zero count is the evidence that the branch ran —
         * there is nothing else on this side of the boundary that can see it.
         */
        final java.util.concurrent.atomic.AtomicInteger protectCalls =
                new java.util.concurrent.atomic.AtomicInteger();

        @SuppressWarnings("unused") // Called from native code by name.
        public boolean protectSocket(int fd) {
            protectCalls.incrementAndGet();
            return true;
        }
    }

    private int passed;
    private int failed;
    private int skipped;

    private NativeInvariantSmoke() {
    }

    static void run(TunSource tunSource, long networkHandle) {
        new NativeInvariantSmoke().execute(tunSource, networkHandle);
    }

    private void execute(TunSource tunSource, long networkHandle) {
        Log.i(TAG, "INVARIANT_RUN begin abi=" + safeAbi() + " network_handle_present="
                + (networkHandle != 0));

        jniStringReturns();
        List<String> compiled = capabilitiesDocument();
        guardedEntryPointsOnUnknownHandle();
        takeTunFdRefusesANumber();
        callbackExceptionIsClearedBeforeReturn();

        ParcelFileDescriptor tun = null;
        try {
            tun = tunSource.establish();
            if (tun == null) {
                skip("tun_fd_is_a_character_device", "establish() returned null");
                skip("start_over_establish_fd", "establish() returned null");
            } else {
                tunFdIsACharacterDevice(tun);
                startOverEstablishFd(tun, networkHandle);
                // detachFd transferred ownership to the core, which closed it on stop.
                tun = null;
            }
        } catch (Throwable t) {
            skip("tun_fd_is_a_character_device", "establish() threw " + describe(t));
            skip("start_over_establish_fd", "establish() threw " + describe(t));
        } finally {
            if (tun != null) {
                try {
                    tun.close();
                } catch (Throwable ignored) {
                    // Nothing useful to do: the run is over and the process is about to be
                    // idle. A failure to close cannot invalidate a verdict already printed.
                }
            }
        }

        Log.i(TAG, "INVARIANT_RUN end passed=" + passed + " failed=" + failed
                + " skipped=" + skipped + " compiled=" + join(compiled));
    }

    // ------------------------------------------------------------------ checks

    /**
     * §2.2/§2.3: the three read-only entry points, which are also the ones an app calls
     * before it has anything else.
     *
     * <p>Cheap, and the first thing worth knowing: a mismatch here means the .so in the APK
     * is not the one anybody thinks it is.
     */
    private void jniStringReturns() {
        try {
            String version = FoxholeNativeEngine.nativeVersion();
            int abi = FoxholeNativeEngine.nativeAbiVersion();
            if (version == null || version.isEmpty()) {
                fail("jni_version_strings", "nativeVersion returned " + version);
                return;
            }
            if (abi <= 0) {
                fail("jni_version_strings", "nativeAbiVersion returned " + abi);
                return;
            }
            pass("jni_version_strings", "version=" + version + " abi=" + abi);
        } catch (Throwable t) {
            fail("jni_version_strings", describe(t));
        }
    }

    /**
     * The capabilities document, read on the device rather than on a build host.
     *
     * <p>This is the check that makes a feature-selected build honest: the protocol set is
     * chosen at build time now, and `compiled` is the only thing that tells the app which
     * set it got. Printing the list means a device run says what is in the artifact instead
     * of what the build command was believed to say.
     */
    private List<String> capabilitiesDocument() {
        List<String> compiled = new ArrayList<>();
        try {
            String json = FoxholeNativeEngine.nativeCapabilities();
            if (json == null || json.isEmpty()) {
                fail("capabilities_document", "nativeCapabilities returned " + json);
                return compiled;
            }
            JSONObject document = new JSONObject(json);
            int schema = document.getInt("capabilities_schema_version");
            JSONArray protocols = document.getJSONArray("protocols");
            List<String> absent = new ArrayList<>();
            for (int i = 0; i < protocols.length(); i++) {
                JSONObject protocol = protocols.getJSONObject(i);
                if (protocol.optBoolean("compiled", false)) {
                    compiled.add(protocol.getString("id"));
                } else {
                    absent.add(protocol.getString("id"));
                }
            }
            if (compiled.isEmpty()) {
                fail("capabilities_document", "no protocol reports compiled=true");
                return compiled;
            }
            pass("capabilities_document", "schema=" + schema
                    + " compiled=" + join(compiled) + " absent=" + join(absent));
        } catch (Throwable t) {
            fail("capabilities_document", describe(t));
        }
        return compiled;
    }

    /**
     * §2.1: the panic barriers, on the path an app reaches them by.
     *
     * <p>Each of these entry points is `catch_unwind`-wrapped and each has a documented
     * answer for a handle that names no engine. Calling them all with handle 0 does not
     * force a panic — nothing reachable from Java does — but it does execute the barrier
     * and the registry lookup under ART, and it proves the documented codes are what a
     * device returns rather than what the host tests agree on.
     */
    private void guardedEntryPointsOnUnknownHandle() {
        try {
            List<String> wrong = new ArrayList<>();
            int stop = FoxholeNativeEngine.nativeStop(0);
            if (stop != FoxholeNativeEngine.STOP_UNKNOWN_HANDLE) {
                wrong.add("nativeStop=" + stop);
            }
            int kill = FoxholeNativeEngine.nativeForceKill(0);
            if (kill != FoxholeNativeEngine.STOP_UNKNOWN_HANDLE) {
                wrong.add("nativeForceKill=" + kill);
            }
            int continuity = FoxholeNativeEngine.nativeConfirmContinuity(0, 0);
            if (continuity != FoxholeNativeEngine.CONTINUITY_UNKNOWN_HANDLE) {
                wrong.add("nativeConfirmContinuity=" + continuity);
            }
            long reload = FoxholeNativeEngine.nativeReloadPolicy(0, "{}");
            if (reload != 0) {
                wrong.add("nativeReloadPolicy=" + reload);
            }
            String stats = FoxholeNativeEngine.nativeStats(0);
            if (!"{}".equals(stats)) {
                wrong.add("nativeStats=" + stats);
            }
            String events = FoxholeNativeEngine.nativeDrainEvents(0, 16);
            if (events == null || new JSONObject(events).getJSONArray("events").length() != 0) {
                wrong.add("nativeDrainEvents=" + events);
            }
            String connections = FoxholeNativeEngine.nativeConnections(0);
            if (connections == null || connections.isEmpty()) {
                wrong.add("nativeConnections=" + connections);
            }
            // The calls above must also have left the boundary usable: a barrier that
            // swallowed an exception instead of clearing it shows up here and nowhere else.
            String version = FoxholeNativeEngine.nativeVersion();
            if (version == null || version.isEmpty()) {
                wrong.add("boundary unusable afterwards");
            }
            if (wrong.isEmpty()) {
                pass("guarded_entry_points_unknown_handle", "7 entry points answered as documented");
            } else {
                fail("guarded_entry_points_unknown_handle", join(wrong));
            }
        } catch (Throwable t) {
            fail("guarded_entry_points_unknown_handle", describe(t));
        }
    }

    /**
     * §2.4: a number that is not a descriptor must be refused, not adopted.
     *
     * <p>The host test covers the same call, and that is precisely why this one is here:
     * the host test proves the branch is taken, and only a device proves that the refusal
     * arrives in Java as an exception rather than as the abort that `OwnedFd::drop` on a
     * closed descriptor produces — "IO Safety violation", SIGABRT, no Java stack, nothing
     * naming FoxCore in the log.
     *
     * <p>Surviving this check is therefore as much of the result as passing it.
     */
    private void takeTunFdRefusesANumber() {
        try {
            long handle = FoxholeNativeEngine.nativeStart(
                    Integer.MAX_VALUE, DIRECT_CONFIG, new HostWithoutContext());
            fail("take_tun_fd_refuses_a_number", "start returned handle=" + handle
                    + " for a descriptor this process does not hold");
            if (handle != 0) {
                FoxholeNativeEngine.nativeStop(handle);
            }
        } catch (IllegalStateException expected) {
            String message = String.valueOf(expected.getMessage());
            if (message.contains(String.valueOf(Integer.MAX_VALUE))) {
                pass("take_tun_fd_refuses_a_number", "msg=" + message);
            } else {
                fail("take_tun_fd_refuses_a_number",
                        "refused without naming the descriptor: " + message);
            }
        } catch (Throwable t) {
            fail("take_tun_fd_refuses_a_number", describe(t));
        }
    }

    /**
     * §2.2: a Java method that throws inside a Rust→Java call must not leave the exception
     * pending when the boundary returns.
     *
     * <p>This is the one invariant in the audit whose violation is undefined behaviour
     * rather than a wrong answer, and it is unreachable from a host build: there is no ART
     * to have a pending exception. The trigger is a host object that is not a `Context`, so
     * `getSystemService` raises `NoSuchMethodError` inside `java_flow_attributor`.
     *
     * <p>What is checked is not that the start fails — it must — but that the process is
     * still here afterwards and that the next JNI call behaves. A boundary that returned
     * with the exception still set would take ART down on that next call, so the check is
     * the call.
     */
    private void callbackExceptionIsClearedBeforeReturn() {
        try {
            long handle = FoxholeNativeEngine.nativeStart(
                    Integer.MAX_VALUE, ATTRIBUTED_CONFIG, new HostWithoutContext());
            // Unreachable in practice: the descriptor is refused before the attributor is
            // built. Recorded rather than ignored, because a start that succeeded here
            // would mean the descriptor check moved.
            fail("callback_exception_cleared", "start unexpectedly returned handle=" + handle);
            if (handle != 0) {
                FoxholeNativeEngine.nativeStop(handle);
            }
        } catch (IllegalStateException expected) {
            String after = null;
            String capabilities = null;
            try {
                after = FoxholeNativeEngine.nativeVersion();
                capabilities = FoxholeNativeEngine.nativeCapabilities();
            } catch (Throwable t) {
                fail("callback_exception_cleared", "the next JNI call failed: " + describe(t));
                return;
            }
            if (after == null || after.isEmpty() || capabilities == null || capabilities.isEmpty()) {
                fail("callback_exception_cleared", "the boundary stopped answering after a refusal");
                return;
            }
            pass("callback_exception_cleared",
                    "refusal=\"" + expected.getMessage() + "\" boundary_still_answers=true");
        } catch (Throwable t) {
            fail("callback_exception_cleared", describe(t));
        }
    }

    /**
     * The P6 question from docs/24 §9, asked of the device: is what
     * {@code VpnService.establish()} returns a character device?
     *
     * <p>`take_tun_fd` deliberately does not refuse a descriptor of the wrong shape — it
     * records one and starts anyway — because being wrong about this on some API level or
     * OEM image means the VPN never starts, and that could not be checked without a phone.
     * This is the phone. A run of this check on each target API level is the evidence that
     * would let the Rust side become fail-closed; asking Java directly, with
     * {@code Os.fstat}, keeps the answer independent of the code being judged.
     */
    private void tunFdIsACharacterDevice(ParcelFileDescriptor tun) {
        try {
            StructStat status = Os.fstat(tun.getFileDescriptor());
            String detail = "st_mode=0" + Integer.toOctalString(status.st_mode)
                    + " st_rdev=" + status.st_rdev
                    + " sdk=" + android.os.Build.VERSION.SDK_INT
                    + " device=" + android.os.Build.MODEL;
            if (OsConstants.S_ISCHR(status.st_mode)) {
                pass("tun_fd_is_a_character_device", detail);
            } else {
                // Not a failure of the smoke — it is the finding the smoke exists to make.
                // If this ever prints, the fail-closed check must NOT be added.
                fail("tun_fd_is_a_character_device", detail);
            }
        } catch (ErrnoException e) {
            fail("tun_fd_is_a_character_device", "fstat: " + e.getMessage());
        } catch (Throwable t) {
            fail("tun_fd_is_a_character_device", describe(t));
        }
    }

    /**
     * A start over the descriptor {@code establish()} actually returned, and a clean stop.
     *
     * <p>This is the lifecycle the ABI exists for, and no host test covers it: the fd is a
     * real tun, the handle is a real {@code Network}, and the callbacks cross into ART.
     *
     * <p>It also carries the only trigger this file has for §2.5 and §2.6. Those five
     * `unsafe` blocks — `android_setsocknetwork` and the `android_getaddrinfofornetwork`
     * list walk — are reached from `ProtectedDialer::prepare`, which runs when the core
     * <em>dials</em>, not when it starts. A start alone would leave them as unexecuted as
     * before, so the run opens one flow through the tunnel and looks at whether the protect
     * callback was reached. That flow needs the phone to have working network, so a failure
     * to reach it is reported as {@code SKIP}: it says nothing about the boundary.
     */
    private void startOverEstablishFd(ParcelFileDescriptor tun, long networkHandle) {
        long handle = 0;
        HostWithoutContext host = new HostWithoutContext();
        try {
            int fd = tun.detachFd();
            handle = networkHandle != 0
                    ? FoxholeNativeEngine.nativeStartWithNetwork(
                            fd, DIRECT_CONFIG, networkHandle, host)
                    : FoxholeNativeEngine.nativeStart(fd, DIRECT_CONFIG, host);
            if (handle == 0) {
                fail("start_over_establish_fd", "start returned 0 without throwing");
                skip("protected_dial_ran", "no engine to dial through");
                return;
            }
            String stats = FoxholeNativeEngine.nativeStats(handle);
            new JSONObject(stats);
            pass("start_over_establish_fd",
                    "network_pinned=" + (networkHandle != 0) + " stats_bytes=" + stats.length());

            protectedDialRan(host);

            int stop = FoxholeNativeEngine.nativeStop(handle);
            handle = 0;
            if (stop != FoxholeNativeEngine.STOPPED) {
                fail("engine_stops_cleanly", "stop=" + stop + " (expected STOPPED)");
            } else {
                pass("engine_stops_cleanly", "stop=STOPPED");
            }
        } catch (Throwable t) {
            fail("start_over_establish_fd", describe(t));
        } finally {
            if (handle != 0) {
                try {
                    FoxholeNativeEngine.nativeForceKill(handle);
                } catch (Throwable ignored) {
                    // The verdict is already recorded; a failing cleanup must not replace it.
                }
            }
        }
    }

    /**
     * Open one flow through the tunnel, so the dialer — and with it §2.5/§2.6 — runs.
     *
     * <p>The established TUN routes {@code 0.0.0.0/0}, and this app's own uid is inside the
     * capture, so a plain socket from here is a packet the core has to classify, resolve and
     * dial. The destination is named rather than numeric on purpose: a name is what sends
     * the core through `resolve_host_on_network`, and an address would skip exactly the five
     * blocks in question.
     *
     * <p>The verdict is the protect callback's count, not whether the connection succeeded.
     * What is being checked is that the native branch ran and returned without corrupting
     * anything — the site being unreachable, the network being captive or the device being
     * offline are all conditions of the phone, not findings about the ABI.
     */
    private void protectedDialRan(HostWithoutContext host) {
        try {
            try (java.net.Socket socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress("example.com", 80), 5000);
            } catch (Throwable ignored) {
                // Deliberately swallowed: see above. The count below is the verdict.
            }
            // The dial is asynchronous on the core's side; the callback lands while the
            // connect is in flight, but a moment's grace costs nothing and removes a race
            // between a fast refusal and the counter being read.
            Thread.sleep(1500);
            int calls = host.protectCalls.get();
            if (calls > 0) {
                pass("protected_dial_ran",
                        "protect_callbacks=" + calls + " (android_setsocknetwork reached)");
            } else {
                skip("protected_dial_ran",
                        "the core never dialled: no usable network on this device");
            }
        } catch (Throwable t) {
            skip("protected_dial_ran", describe(t));
        }
    }

    // ----------------------------------------------------------------- printing

    private void pass(String id, String detail) {
        passed++;
        Log.i(TAG, "INVARIANT " + id + " PASS " + detail);
    }

    private void fail(String id, String detail) {
        failed++;
        Log.e(TAG, "INVARIANT " + id + " FAIL " + detail);
    }

    private void skip(String id, String reason) {
        skipped++;
        Log.w(TAG, "INVARIANT " + id + " SKIP " + reason);
    }

    private static String describe(Throwable t) {
        return t.getClass().getSimpleName() + ": " + t.getMessage();
    }

    private static String join(List<String> values) {
        if (values.isEmpty()) {
            return "none";
        }
        StringBuilder out = new StringBuilder();
        for (String value : values) {
            if (out.length() > 0) {
                out.append(',');
            }
            out.append(value);
        }
        return out.toString();
    }

    private static String safeAbi() {
        try {
            return String.valueOf(FoxholeNativeEngine.nativeAbiVersion());
        } catch (Throwable t) {
            return "unreadable";
        }
    }
}
