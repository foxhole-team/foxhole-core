use crate::{CompiledSession, Coverage, Report, Status, limits};
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

struct Owner {
    used: bool,
    session: Option<Arc<CompiledSession>>,
}
static OWNER: Mutex<Owner> = Mutex::new(Owner {
    used: false,
    session: None,
});
#[repr(C)]
pub struct NativeBuffer {
    pointer: *mut u8,
    length: usize,
}
fn bytes(data: Vec<u8>) -> NativeBuffer {
    let mut data = data.into_boxed_slice();
    let output = NativeBuffer {
        pointer: data.as_mut_ptr(),
        length: data.len(),
    };
    std::mem::forget(data);
    output
}
fn response(report: Report) -> NativeBuffer {
    match serde_json::to_vec(&report) {
        Ok(data) if data.len() <= limits::RESPONSE_BYTES => bytes(data),
        _ => bytes(br#"{"protocolVersion":1,"sessionId":0,"status":"error","reason":"response_limit","engine":"yara-x/1.21.0;wasmtime/49.0.4;pulley;profile/sentinel-v2","coverageComplete":false,"requestedBytes":0,"scannedBytes":0,"elapsedMillis":0,"reportingTruncated":false,"diagnosticCount":0,"diagnostics":[],"matches":[]}"#.to_vec()),
    }
}
fn get(id: i64) -> Result<Arc<CompiledSession>, Report> {
    if id != 1 {
        return Err(Report::new(Status::Error, "invalid_session"));
    }
    OWNER
        .lock()
        .map_err(|_| Report::new(Status::Error, "owner_error"))?
        .session
        .clone()
        .ok_or_else(|| Report::new(Status::Error, "session_closed"))
}
fn session_response(id: i64, mut report: Report) -> NativeBuffer {
    report.session_id = if id == 1 { 1 } else { 0 };
    response(report)
}
unsafe fn input<'a>(pointer: *const u8, length: usize, maximum: usize) -> Result<&'a [u8], Report> {
    if length > maximum {
        return Err(Report::new(Status::Inconclusive, "input_limit"));
    }
    if pointer.is_null() {
        return if length == 0 {
            Ok(&[])
        } else {
            Err(Report::new(Status::Error, "input_error"))
        };
    }
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_compile(pointer: *const u8, length: usize) -> NativeBuffer {
    let source = match unsafe { input(pointer, length, limits::SOURCE_BYTES) } {
        Ok(x) => x,
        Err(e) => return response(e),
    };
    {
        let mut owner = match OWNER.lock() {
            Ok(x) => x,
            Err(_) => return response(Report::new(Status::Error, "owner_error")),
        };
        if owner.used {
            return response(Report::new(Status::Unsupported, "process_session_consumed"));
        }
        owner.used = true;
    }
    match CompiledSession::compile(source) {
        Ok(session) => {
            if let Ok(mut owner) = OWNER.lock() {
                owner.session = Some(Arc::new(session));
            } else {
                return response(Report::new(Status::Error, "owner_error"));
            }
            session_response(1, Report::new(Status::Complete, "compiled"))
        }
        Err(error) => response(error),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_scan_bytes(
    id: i64,
    pointer: *const u8,
    length: usize,
    complete: i32,
) -> NativeBuffer {
    let result = get(id).and_then(|session| {
        unsafe { input(pointer, length, limits::DATA_BYTES) }.map(|data| {
            session.scan_bytes(
                data,
                if complete == 1 {
                    Coverage::Full
                } else {
                    Coverage::Partial
                },
            )
        })
    });
    session_response(id, result.unwrap_or_else(|e| e))
}
#[unsafe(no_mangle)]
pub extern "C" fn sentinel_scan_fd(
    id: i64,
    fd: i32,
    offset: i64,
    length: i64,
    complete: i32,
) -> NativeBuffer {
    if offset < 0 || length < 0 {
        return session_response(id, Report::new(Status::Error, "invalid_range"));
    }
    let result = get(id).map(|session| {
        session.scan_fd(
            fd,
            offset as u64,
            length as u64,
            if complete == 1 {
                Coverage::Full
            } else {
                Coverage::Partial
            },
        )
    });
    session_response(id, result.unwrap_or_else(|e| e))
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_accept_blob(
    id: i64,
    pointer: *const u8,
    length: usize,
) -> NativeBuffer {
    let result = get(id).and_then(|session| {
        unsafe { input(pointer, length, limits::COMPILED_BYTES) }
            .and_then(|data| session.accept_owned_blob(data))
    });
    session_response(
        id,
        result
            .map(|_| Report::new(Status::Complete, "owned_compiled_reused"))
            .unwrap_or_else(|e| e),
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn sentinel_blob(id: i64) -> NativeBuffer {
    get(id)
        .and_then(|s| s.compiled_blob())
        .map(bytes)
        .unwrap_or(NativeBuffer {
            pointer: std::ptr::null_mut(),
            length: 0,
        })
}
#[unsafe(no_mangle)]
pub extern "C" fn sentinel_cancel(id: i64, close: i32) -> NativeBuffer {
    match get(id) {
        Ok(session) => {
            session.request_cancel();
            if close == 1
                && let Ok(mut owner) = OWNER.lock()
            {
                owner.session = None;
            }
            session_response(
                id,
                Report::new(Status::Cancelled, "cancel_requested_settlement_required"),
            )
        }
        Err(e) => session_response(id, e),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sentinel_free(buffer: NativeBuffer) {
    if !buffer.pointer.is_null() {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                buffer.pointer,
                buffer.length,
            )));
        }
    }
}
unsafe extern "C" {
    fn sentinel_readonly_regular_fd(fd: i32) -> i32;
    fn jni_compile(env: *mut c_void, source: *mut c_void) -> *mut c_void;
    fn jni_scan_bytes(env: *mut c_void, id: i64, data: *mut c_void, complete: u8) -> *mut c_void;
    fn jni_scan_fd(
        env: *mut c_void,
        id: i64,
        fd: i32,
        offset: i64,
        length: i64,
        complete: u8,
    ) -> *mut c_void;
    fn jni_accept_blob(env: *mut c_void, id: i64, blob: *mut c_void) -> *mut c_void;
    fn jni_blob(env: *mut c_void, id: i64) -> *mut c_void;
    fn jni_cancel(env: *mut c_void, id: i64, close: u8) -> *mut c_void;
}
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_: *mut c_void, _: *mut c_void) -> i32 {
    #[cfg(target_os = "android")]
    if !(99_000..=99_999).contains(&(unsafe { libc::getuid() } % 100_000)) {
        return -1;
    }
    0x0001_0006
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeCompile(
    env: *mut c_void,
    _: *mut c_void,
    source: *mut c_void,
) -> *mut c_void {
    unsafe { jni_compile(env, source) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeScanBytes(
    env: *mut c_void,
    _: *mut c_void,
    id: i64,
    data: *mut c_void,
    complete: u8,
) -> *mut c_void {
    unsafe { jni_scan_bytes(env, id, data, complete) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeScanFd(
    env: *mut c_void,
    _: *mut c_void,
    id: i64,
    fd: i32,
    offset: i64,
    length: i64,
    complete: u8,
) -> *mut c_void {
    unsafe { jni_scan_fd(env, id, fd, offset, length, complete) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeAcceptOwnedBlob(
    env: *mut c_void,
    _: *mut c_void,
    id: i64,
    blob: *mut c_void,
) -> *mut c_void {
    unsafe { jni_accept_blob(env, id, blob) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeCompiledBlob(
    env: *mut c_void,
    _: *mut c_void,
    id: i64,
) -> *mut c_void {
    unsafe { jni_blob(env, id) }
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeCancel(
    env: *mut c_void,
    _: *mut c_void,
    id: i64,
    close: u8,
) -> *mut c_void {
    unsafe { jni_cancel(env, id, close) }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_foxhole_guard_sentinel_nativeengine_NativeYara_nativeIsReadonlyRegularFd(
    _: *mut c_void,
    _: *mut c_void,
    fd: i32,
) -> u8 {
    u8::from(unsafe { sentinel_readonly_regular_fd(fd) } == 1)
}
