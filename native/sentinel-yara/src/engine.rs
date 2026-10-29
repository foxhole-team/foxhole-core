use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use yara_x::{Rules, Scanner};
use yara_x_parser::{
    Parser,
    ast::{AST, Item},
    cst::{CSTStream, Event, SyntaxKind},
};

pub mod limits {
    pub const SOURCE_BYTES: usize = 256 * 1024;
    pub const COMPILED_BYTES: usize = 4 * 1024 * 1024;
    pub const DATA_BYTES: usize = 16 * 1024 * 1024;
    pub const RULES: usize = 512;
    pub const PATTERNS_PER_RULE: usize = 64;
    pub const PATTERNS_TOTAL: usize = 1024;
    pub const SYNTAX_NODES: usize = 32_768;
    pub const NESTING: usize = 64;
    pub const LITERAL_BYTES: usize = 64 * 1024;
    pub const IDENTIFIER_BYTES: usize = 128;
    pub const INTERNAL_MATCHES: usize = 256;
    pub const MATCHING_RULES: usize = 64;
    pub const REPORTED_PATTERNS: usize = 8;
    pub const REPORTED_OFFSETS: usize = 128;
    pub const DIAGNOSTICS: usize = 8;
    pub const TIMEOUT_SECONDS: u64 = 2;
    pub const RESPONSE_BYTES: usize = 256 * 1024;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Partial,
    Timeout,
    Unsupported,
    Inconclusive,
    Cancelled,
    Error,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    Full,
    Partial,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Offset {
    pub start: u64,
    pub length: u64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternEvidence {
    pub pattern_id: String,
    pub offsets: Vec<Offset>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleEvidence {
    pub rule_id: String,
    pub patterns: Vec<PatternEvidence>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub protocol_version: u32,
    pub session_id: u64,
    pub status: Status,
    pub reason: &'static str,
    pub engine: &'static str,
    pub coverage_complete: bool,
    pub requested_bytes: u64,
    pub scanned_bytes: u64,
    pub elapsed_millis: u64,
    pub reporting_truncated: bool,
    pub diagnostic_count: usize,
    pub diagnostics: Box<[&'static str]>,
    pub matches: Vec<RuleEvidence>,
}
impl Report {
    pub(crate) fn new(status: Status, reason: &'static str) -> Self {
        Self {
            protocol_version: 1,
            session_id: 0,
            status,
            reason,
            engine: "yara-x/1.21.0;wasmtime/49.0.4;pulley;profile/sentinel-v2",
            coverage_complete: false,
            requested_bytes: 0,
            scanned_bytes: 0,
            elapsed_millis: 0,
            reporting_truncated: false,
            diagnostic_count: 0,
            diagnostics: Box::new([]),
            matches: Vec::new(),
        }
    }
    fn diagnostics(mut self, code: &'static str, count: usize) -> Self {
        self.diagnostic_count = count;
        self.diagnostics = vec![code; count.min(limits::DIAGNOSTICS)].into_boxed_slice();
        self
    }
}
struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > limits::COMPILED_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("compiled budget"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn preflight(source: &[u8]) -> Result<(), Report> {
    if source.len() > limits::SOURCE_BYTES {
        return Err(Report::new(Status::Inconclusive, "source_limit"));
    }
    if source.is_empty() || std::str::from_utf8(source).is_err() {
        return Err(Report::new(Status::Unsupported, "source_encoding"));
    }
    let (mut nodes, mut depth, mut literals, mut errors) = (0usize, 0usize, 0usize, 0usize);
    let stream = CSTStream::from(Parser::new(source))
        .whitespaces(false)
        .newlines(false)
        .comments(false);
    for event in stream {
        match event {
            Event::Begin { kind, span } => {
                if kind == SyntaxKind::INCLUDE_STMT {
                    return Err(Report::new(Status::Unsupported, "includes_forbidden"));
                }
                if kind == SyntaxKind::HEX_PATTERN {
                    literals += span.len();
                    if literals > limits::LITERAL_BYTES {
                        return Err(Report::new(Status::Inconclusive, "literal_limit"));
                    }
                }
                nodes += 1;
                depth += 1;
                if nodes > limits::SYNTAX_NODES || depth > limits::NESTING {
                    return Err(Report::new(Status::Inconclusive, "syntax_budget"));
                }
            }
            Event::End { .. } => depth = depth.saturating_sub(1),
            Event::Token { kind, span } => {
                if matches!(kind, SyntaxKind::STRING_LIT | SyntaxKind::REGEXP) {
                    literals += span.len();
                    if literals > limits::LITERAL_BYTES {
                        return Err(Report::new(Status::Inconclusive, "literal_limit"));
                    }
                }
                if kind == SyntaxKind::INCLUDE_KW {
                    return Err(Report::new(Status::Unsupported, "includes_forbidden"));
                }
            }
            Event::Error { .. } => {
                errors += 1;
                if errors >= limits::DIAGNOSTICS {
                    break;
                }
            }
        }
    }
    if errors > 0 {
        return Err(Report::new(Status::Error, "rule_syntax").diagnostics("rule_syntax", errors));
    }
    let ast = AST::from(Parser::new(source));
    let (mut rules, mut patterns) = (0, 0);
    for item in ast.items() {
        match item {
            Item::Include(_) => return Err(Report::new(Status::Unsupported, "includes_forbidden")),
            Item::Import(import)
                if !["dex", "hash", "math", "string"].contains(&import.module_name) =>
            {
                return Err(Report::new(Status::Unsupported, "module_forbidden"));
            }
            Item::Rule(rule) => {
                rules += 1;
                let count = rule.patterns.as_ref().map_or(0, Vec::len);
                patterns += count;
                if rules > limits::RULES
                    || count > limits::PATTERNS_PER_RULE
                    || patterns > limits::PATTERNS_TOTAL
                {
                    return Err(Report::new(Status::Inconclusive, "rule_pattern_limit"));
                }
                if rule.identifier.name.len() > limits::IDENTIFIER_BYTES
                    || rule.patterns.as_ref().is_some_and(|p| {
                        p.iter()
                            .any(|p| p.identifier().name.len() > limits::IDENTIFIER_BYTES)
                    })
                {
                    return Err(Report::new(Status::Inconclusive, "identifier_limit"));
                }
            }
            _ => {}
        }
    }
    if rules == 0 {
        return Err(Report::new(Status::Unsupported, "empty_rules"));
    }
    Ok(())
}
pub struct CompiledSession {
    rules: Rules,
    blob: Vec<u8>,
    cancelled: AtomicBool,
    busy: AtomicBool,
}
impl std::fmt::Debug for CompiledSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompiledSession")
    }
}
struct ScanAdmission<'a>(&'a AtomicBool);
impl Drop for ScanAdmission<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl CompiledSession {
    pub fn compile(source: &[u8]) -> Result<Self, Report> {
        #[cfg(target_os = "android")]
        if !(99_000..=99_999).contains(&(unsafe { libc::getuid() } % 100_000)) {
            return Err(Report::new(Status::Unsupported, "process_not_isolated"));
        }
        preflight(source)?;
        let mut compiler = yara_x::Compiler::new();
        compiler
            .enable_includes(false)
            .colorize_errors(false)
            .max_warnings(limits::DIAGNOSTICS)
            .error_on_slow_pattern(true)
            .error_on_slow_loop(true)
            .condition_optimization(false);
        for module in [
            "console", "vt", "cuckoo", "zip", "pe", "elf", "macho", "dotnet", "magic", "time",
            "crx", "lnk", "msi", "olecf", "vba",
        ] {
            compiler.ban_module(
                module,
                "module_forbidden",
                "module is outside the static scanner profile",
            );
        }
        if compiler.add_source(source).is_err() {
            return Err(Report::new(Status::Error, "rule_rejected")
                .diagnostics("rule_rejected", compiler.errors().len()));
        }
        let rules = compiler.build();
        if rules
            .imports()
            .any(|m| !["dex", "hash", "math", "string"].contains(&m))
        {
            return Err(Report::new(Status::Unsupported, "module_forbidden"));
        }
        let mut blob = BoundedWriter(Vec::new());
        rules
            .serialize_into(&mut blob)
            .map_err(|_| Report::new(Status::Inconclusive, "compiled_limit"))?;
        Ok(Self {
            rules,
            blob: blob.0,
            cancelled: AtomicBool::new(false),
            busy: AtomicBool::new(false),
        })
    }
    pub fn compiled_blob(&self) -> Result<Vec<u8>, Report> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Report::new(Status::Cancelled, "cancel_requested"));
        }
        Ok(self.blob.clone())
    }
    pub fn accept_owned_blob(&self, blob: &[u8]) -> Result<(), Report> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Report::new(Status::Cancelled, "cancel_requested"));
        }
        // Upstream excludes deserializing third-party manipulated blobs.
        if blob.len() > limits::COMPILED_BYTES || blob != self.blob {
            return Err(Report::new(Status::Unsupported, "unowned_compiled_blob"));
        }
        Ok(())
    }
    pub fn request_cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn cancellation_interrupts_native(&self) -> bool {
        false
    }
    fn admit(&self) -> Result<ScanAdmission<'_>, Report> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Report::new(Status::Cancelled, "cancel_requested"));
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Report::new(Status::Error, "session_busy"))?;
        Ok(ScanAdmission(&self.busy))
    }
    pub fn scan_bytes(&self, data: &[u8], coverage: Coverage) -> Report {
        let started = Instant::now();
        let mut report = match self.admit() {
            Ok(_admission) => self.scan_owned(data, coverage),
            Err(error) => error,
        };
        report.requested_bytes = data.len() as u64;
        report.elapsed_millis = started.elapsed().as_millis() as u64;
        report
    }
    fn scan_owned(&self, data: &[u8], coverage: Coverage) -> Report {
        if data.len() > limits::DATA_BYTES {
            return Report::new(Status::Inconclusive, "data_limit");
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Report::new(Status::Cancelled, "cancel_requested");
        }
        let mut scanner = Scanner::new(&self.rules);
        // Timeout starts a permanent heartbeat; the isolated owner must terminate its process.
        scanner
            .set_timeout(Duration::from_secs(limits::TIMEOUT_SECONDS))
            .use_mmap(false)
            .fast_scan(true)
            .max_matches_per_pattern(limits::INTERNAL_MATCHES)
            .match_context_size(0);
        let scanned = scanner.scan(data);
        if self.cancelled.load(Ordering::Acquire) {
            return Report::new(Status::Cancelled, "cancel_requested");
        }
        let results = match scanned {
            Ok(results) => results,
            Err(yara_x::ScanError::Timeout) => {
                return Report::new(Status::Timeout, "engine_timeout");
            }
            Err(_) => return Report::new(Status::Error, "engine_error"),
        };
        // A cap can change #/@/! predicates, including in nonmatching private rules.
        let saturated = results
            .matching_rules()
            .include_private(true)
            .chain(results.non_matching_rules().include_private(true))
            .any(|r| {
                r.patterns()
                    .include_private(true)
                    .any(|p| p.matches().count() >= limits::INTERNAL_MATCHES)
            });
        if saturated {
            return Report::new(Status::Inconclusive, "match_tracking_limit");
        }
        let mut report = Report::new(
            if coverage == Coverage::Full {
                Status::Complete
            } else {
                Status::Partial
            },
            if coverage == Coverage::Full {
                "scanned"
            } else {
                "caller_incomplete_input"
            },
        );
        report.scanned_bytes = data.len() as u64;
        report.coverage_complete = coverage == Coverage::Full;
        let mut offset_count = 0;
        for rule in results.matching_rules() {
            if report.matches.len() == limits::MATCHING_RULES {
                report.reporting_truncated = true;
                break;
            }
            let mut evidence = RuleEvidence {
                rule_id: rule.identifier().to_owned(),
                patterns: Vec::new(),
            };
            for pattern in rule.patterns() {
                if pattern.matches().next().is_none() {
                    continue;
                }
                if evidence.patterns.len() == limits::REPORTED_PATTERNS {
                    report.reporting_truncated = true;
                    break;
                }
                let mut item = PatternEvidence {
                    pattern_id: pattern.identifier().to_owned(),
                    offsets: Vec::new(),
                };
                for found in pattern.matches() {
                    if offset_count == limits::REPORTED_OFFSETS {
                        report.reporting_truncated = true;
                        break;
                    }
                    let range = found.range();
                    item.offsets.push(Offset {
                        start: range.start as u64,
                        length: range.len() as u64,
                    });
                    offset_count += 1;
                }
                evidence.patterns.push(item);
            }
            report.matches.push(evidence);
        }
        if report.reporting_truncated {
            report.status = Status::Partial;
            report.reason = "reporting_limit";
            report.coverage_complete = false;
            report.matches.clear();
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Report::new(Status::Cancelled, "cancel_requested");
        }
        report
    }
    pub fn scan_fd(&self, fd: i32, offset: u64, length: u64, coverage: Coverage) -> Report {
        let started = Instant::now();
        let mut report = match self.admit() {
            Ok(_admission) => self.read_and_scan(fd, offset, length, coverage),
            Err(error) => error,
        };
        report.requested_bytes = length;
        report.elapsed_millis = started.elapsed().as_millis() as u64;
        report
    }
    fn read_and_scan(&self, fd: i32, offset: u64, length: u64, coverage: Coverage) -> Report {
        if length > limits::DATA_BYTES as u64 {
            return Report::new(Status::Inconclusive, "data_limit");
        }
        if offset
            .checked_add(length)
            .is_none_or(|n| n > i64::MAX as u64)
        {
            return Report::new(Status::Error, "invalid_range");
        }
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Report::new(Status::Error, "descriptor_error");
        }
        let owned = unsafe { OwnedFd::from_raw_fd(duplicated) };
        let flags = unsafe { libc::fcntl(duplicated, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Report::new(Status::Unsupported, "descriptor_not_readonly");
        }
        let file = File::from(owned);
        let before = match file.metadata() {
            Ok(m) if m.is_file() => m,
            Ok(_) => return Report::new(Status::Unsupported, "descriptor_not_regular"),
            Err(_) => return Report::new(Status::Error, "descriptor_error"),
        };
        if offset + length > before.len() {
            return Report::new(Status::Partial, "truncated_descriptor");
        }
        let mut data = vec![0; length as usize];
        let mut consumed = 0;
        while consumed < data.len() {
            if self.cancelled.load(Ordering::Acquire) {
                return Report::new(Status::Cancelled, "cancel_requested");
            }
            let end = (consumed + 64 * 1024).min(data.len());
            match file.read_at(&mut data[consumed..end], offset + consumed as u64) {
                Ok(0) => return Report::new(Status::Partial, "truncated_descriptor"),
                Ok(n) => consumed += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Report::new(Status::Error, "descriptor_read_error"),
            }
        }
        let same = file.metadata().is_ok_and(|after| {
            before.len() == after.len()
                && before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec()
        });
        if !same {
            return Report::new(Status::Partial, "descriptor_changed");
        }
        self.scan_owned(&data, coverage)
    }
}
