use std::io;

use foxcore_api::FlowIdentity;

pub(super) const MAX_PACKAGES: usize = 32;

#[derive(Clone, Default)]
pub(super) struct PackageIdentity {
    pub packages: Vec<String>,
    pub signing_digest: Option<[u8; 32]>,
}

impl PackageIdentity {
    pub fn bind(self, uid: u32) -> FlowIdentity {
        FlowIdentity {
            uid,
            packages: self.packages,
            signing_digest: self.signing_digest,
        }
    }
}

pub(super) struct DecodedIdentity {
    pub identity: PackageIdentity,
    pub cacheable: bool,
}

pub(super) trait PackageArrayReader {
    fn package_count(&mut self) -> io::Result<usize>;
    fn package(&mut self, index: usize) -> io::Result<Option<String>>;
    fn signing_digest(&mut self, package: &str) -> io::Result<Option<[u8; 32]>>;
}

pub(super) fn decode_identity(reader: &mut impl PackageArrayReader) -> DecodedIdentity {
    match read_identity(reader) {
        Ok(identity) => DecodedIdentity {
            identity,
            cacheable: true,
        },
        Err(_) => DecodedIdentity {
            identity: PackageIdentity::default(),
            cacheable: false,
        },
    }
}

fn read_identity(reader: &mut impl PackageArrayReader) -> io::Result<PackageIdentity> {
    let length = reader.package_count()?;
    if length > MAX_PACKAGES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete Android package identity",
        ));
    }
    let mut packages = Vec::with_capacity(length);
    for index in 0..length {
        let package = reader
            .package(index)?
            .ok_or_else(|| io::Error::other("missing Android package"))?;
        if package.trim().is_empty() || package.len() > 255 || package.chars().any(char::is_control)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Android package identity",
            ));
        }
        packages.push(package);
    }
    let signing_digest = match super::unique_package_for_signing_digest(&packages) {
        Some(package) => reader.signing_digest(package)?,
        None => None,
    };
    Ok(PackageIdentity {
        packages,
        signing_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Reader {
        count: usize,
        values: Vec<Option<String>>,
        reads: usize,
        digest_reads: usize,
        fail_at: Option<usize>,
        fail_digest: bool,
        digest: Option<[u8; 32]>,
    }
    impl Reader {
        fn group(count: usize) -> Self {
            Self {
                count,
                values: (0..count)
                    .map(|index| Some(format!("com.example.p{index}")))
                    .collect(),
                reads: 0,
                digest_reads: 0,
                fail_at: None,
                fail_digest: false,
                digest: Some([0x5a; 32]),
            }
        }
    }
    impl PackageArrayReader for Reader {
        fn package_count(&mut self) -> io::Result<usize> {
            Ok(self.count)
        }
        fn package(&mut self, index: usize) -> io::Result<Option<String>> {
            self.reads += 1;
            if self.fail_at == Some(index) {
                return Err(io::Error::other("package callback failed"));
            }
            Ok(self.values[index].clone())
        }
        fn signing_digest(&mut self, _: &str) -> io::Result<Option<[u8; 32]>> {
            self.digest_reads += 1;
            if self.fail_digest {
                return Err(io::Error::other("digest callback failed"));
            }
            Ok(self.digest)
        }
    }
    fn uid_only(result: DecodedIdentity) {
        assert!(!result.cacheable);
        let identity = result.identity.bind(12345);
        assert_eq!(identity.uid, 12345);
        assert!(identity.packages.is_empty());
        assert_eq!(identity.signing_digest, None);
    }
    #[test]
    fn oversized_shared_uid_never_returns_a_prefix_or_reads_elements() {
        let mut reader = Reader::group(33);
        reader.values[32] = Some("com.example.not_allowlisted".into());
        uid_only(decode_identity(&mut reader));
        assert_eq!(reader.reads, 0);
        assert_eq!(reader.digest_reads, 0);
    }
    #[test]
    fn exact_cap_complete_group_preserves_every_name_and_skips_unique_digest() {
        let mut reader = Reader::group(32);
        let result = decode_identity(&mut reader);
        assert!(result.cacheable);
        assert_eq!(result.identity.packages.len(), 32);
        assert_eq!(result.identity.packages[31], "com.example.p31");
        assert_eq!(reader.reads, 32);
        assert_eq!(reader.digest_reads, 0);
    }
    #[test]
    fn an_invalid_entry_discards_the_entire_group_without_signing_work() {
        for invalid in [
            "",
            " \t ",
            "com.example.\0bad",
            "com.example.\nbad",
            &"a".repeat(256),
            &"é".repeat(128),
        ] {
            let mut reader = Reader::group(2);
            reader.values[1] = Some(invalid.into());
            uid_only(decode_identity(&mut reader));
            assert_eq!(reader.digest_reads, 0);
        }
    }
    #[test]
    fn raw_authorization_names_are_not_trimmed_or_normalized() {
        let mut reader = Reader::group(1);
        reader.values[0] = Some(" com.Example.raw ".into());
        let result = decode_identity(&mut reader);
        assert!(result.cacheable);
        assert_eq!(result.identity.packages, [" com.Example.raw "]);
        assert_eq!(reader.digest_reads, 1);
    }
    #[test]
    fn null_entry_and_callback_errors_preserve_uid_only() {
        let mut reader = Reader::group(2);
        reader.values[1] = None;
        uid_only(decode_identity(&mut reader));
        let mut reader = Reader::group(2);
        reader.fail_at = Some(1);
        uid_only(decode_identity(&mut reader));
        let mut reader = Reader::group(1);
        reader.fail_digest = true;
        uid_only(decode_identity(&mut reader));
    }
    #[test]
    fn valid_optional_digest_none_remains_valid_and_empty_array_is_valid() {
        let mut reader = Reader::group(1);
        reader.digest = None;
        let result = decode_identity(&mut reader);
        assert!(result.cacheable);
        assert_eq!(result.identity.packages.len(), 1);
        assert_eq!(result.identity.signing_digest, None);
        let mut reader = Reader::group(0);
        let result = decode_identity(&mut reader);
        assert!(result.cacheable);
        assert!(result.identity.packages.is_empty());
        assert_eq!(reader.digest_reads, 0);
    }
    #[repr(C)]
    struct ExceptionEnv {
        functions: *const jni::sys::JNINativeInterface_,
        pending: bool,
        clears: usize,
    }
    unsafe extern "system" fn exception_check(env: *mut jni::sys::JNIEnv) -> jni::sys::jboolean {
        // SAFETY: This fixture passes the first field of its live repr(C) ExceptionEnv.
        unsafe { u8::from((*env.cast::<ExceptionEnv>()).pending) }
    }
    unsafe extern "system" fn exception_clear(env: *mut jni::sys::JNIEnv) {
        // SAFETY: This fixture owns the live ExceptionEnv and runs callbacks on one thread.
        unsafe {
            let env = &mut *env.cast::<ExceptionEnv>();
            env.pending = false;
            env.clears += 1;
        }
    }
    struct ExceptionReader<'reader, 'local> {
        env: &'reader mut jni::JNIEnv<'local>,
        fail_stage: usize,
    }
    impl ExceptionReader<'_, '_> {
        fn error(&mut self) -> io::Error {
            io::Error::other(super::super::clear_jni_error(
                self.env,
                "identity metadata callback",
                jni::errors::Error::JavaException,
            ))
        }
    }
    impl PackageArrayReader for ExceptionReader<'_, '_> {
        fn package_count(&mut self) -> io::Result<usize> {
            if self.fail_stage == 0 {
                Err(self.error())
            } else {
                Ok(1)
            }
        }
        fn package(&mut self, _: usize) -> io::Result<Option<String>> {
            if self.fail_stage == 1 {
                Err(self.error())
            } else {
                Ok(Some("com.example.app".into()))
            }
        }
        fn signing_digest(&mut self, _: &str) -> io::Result<Option<[u8; 32]>> {
            Err(self.error())
        }
    }
    #[test]
    fn actual_jni_exception_clear_precedes_uid_only_fallback() {
        // SAFETY: JNI function pointers are nullable; only the two initialized entries are called.
        let mut functions =
            Box::new(unsafe { std::mem::zeroed::<jni::sys::JNINativeInterface_>() });
        functions.ExceptionCheck = Some(exception_check);
        functions.ExceptionClear = Some(exception_clear);
        for stage in 0..3 {
            let mut state = Box::new(ExceptionEnv {
                functions: &*functions,
                pending: true,
                clears: 0,
            });
            // SAFETY: The table and repr(C) state outlive this JNIEnv; callbacks use only those initialized entries.
            let mut env =
                unsafe { jni::JNIEnv::from_raw(std::ptr::addr_of_mut!(state.functions)) }.unwrap();
            let mut reader = ExceptionReader {
                env: &mut env,
                fail_stage: stage,
            };
            uid_only(decode_identity(&mut reader));
            assert!(!state.pending);
            assert_eq!(state.clears, 1);
        }
    }
}
