use foxhole_sentinel_yara::{CompiledSession, Coverage, Status, limits};
use std::io::Write;
use std::os::fd::AsRawFd;
#[path = "support/settlement.rs"]
mod settlement;

const MARKER: &[u8] =
    br#"rule owned_marker { strings: $a = "FOXHOLE_BENIGN_MARKER" condition: $a }"#;

#[test]
fn owned_positive_negative_and_compiled_reuse() {
    let session = CompiledSession::compile(MARKER).unwrap();
    let positive = session.scan_bytes(b"prefix FOXHOLE_BENIGN_MARKER suffix", Coverage::Full);
    assert_eq!(positive.status, Status::Complete);
    assert_eq!(positive.matches[0].rule_id, "owned_marker");
    assert_eq!(positive.matches[0].patterns[0].offsets[0].start, 7);
    assert_eq!(
        session
            .scan_bytes(b"negative", Coverage::Full)
            .matches
            .len(),
        0
    );
    let blob = session.compiled_blob().unwrap();
    assert!(session.accept_owned_blob(&blob).is_ok());
    let mut modified = blob;
    modified[0] ^= 1;
    assert_eq!(
        session.accept_owned_blob(&modified).unwrap_err().status,
        Status::Unsupported
    );
    assert_eq!(
        session
            .scan_bytes(b"FOXHOLE_BENIGN_MARKER", Coverage::Full)
            .matches
            .len(),
        1
    );
}

#[test]
fn truncated_input_and_oversize_never_complete() {
    let session = CompiledSession::compile(MARKER).unwrap();
    let partial = session.scan_bytes(b"negative", Coverage::Partial);
    assert_eq!(partial.status, Status::Partial);
    assert!(!partial.coverage_complete);
    let large = vec![0; limits::DATA_BYTES + 1];
    let rejected = session.scan_bytes(&large, Coverage::Full);
    assert_eq!(rejected.status, Status::Inconclusive);
    assert_eq!(rejected.scanned_bytes, 0);
}

#[test]
fn includes_and_capability_modules_are_rejected_without_raw_diagnostics() {
    for source in [
        br#"include "/private/owned-test-no-file.yar" rule x { condition: true }"#.as_slice(),
        br#"import "console" rule x { condition: console.log("private-body-marker") }"#.as_slice(),
        br#"import "vt" rule x { condition: true }"#.as_slice(),
    ] {
        let error = CompiledSession::compile(source).unwrap_err();
        assert_eq!(error.status, Status::Unsupported);
        assert!(!serde_json::to_string(&error).unwrap().contains("private"));
    }
    let invalid = CompiledSession::compile(b"rule secret_body {").unwrap_err();
    assert!(invalid.diagnostics.len() <= limits::DIAGNOSTICS);
    assert!(
        !serde_json::to_string(&invalid)
            .unwrap()
            .contains("secret_body")
    );
}

#[test]
fn source_rule_pattern_ast_and_literal_budgets_are_admission_limits() {
    assert_eq!(
        CompiledSession::compile(&vec![b' '; limits::SOURCE_BYTES + 1])
            .unwrap_err()
            .status,
        Status::Inconclusive
    );
    let rules = (0..=limits::RULES)
        .map(|n| format!("rule r{n} {{ condition: true }}\n"))
        .collect::<String>();
    assert_eq!(
        CompiledSession::compile(rules.as_bytes())
            .unwrap_err()
            .status,
        Status::Inconclusive
    );
    let patterns = (0..=limits::PATTERNS_PER_RULE)
        .map(|n| format!("$a{n} = \"marker{n}\"\n"))
        .collect::<String>();
    let source = format!("rule x {{ strings: {patterns} condition: any of them }}");
    assert_eq!(
        CompiledSession::compile(source.as_bytes())
            .unwrap_err()
            .status,
        Status::Inconclusive
    );
    let source = format!(
        "rule x {{ strings: $a = \"{}\" condition: $a }}",
        "A".repeat(limits::LITERAL_BYTES + 1)
    );
    assert_eq!(
        CompiledSession::compile(source.as_bytes())
            .unwrap_err()
            .status,
        Status::Inconclusive
    );
    let source = format!(
        "rule x {{ condition: {}true{} }}",
        "(".repeat(limits::NESTING + 1),
        ")".repeat(limits::NESTING + 1)
    );
    assert_eq!(
        CompiledSession::compile(source.as_bytes())
            .unwrap_err()
            .status,
        Status::Inconclusive
    );
}

#[test]
fn capped_match_tracking_does_not_produce_a_false_negative_or_finding() {
    let session = CompiledSession::compile(br#"private rule count_test { strings: $a = "MARK" private condition: #a > 256 } rule visible { condition: count_test }"#).unwrap();
    let result = session.scan_bytes(
        &b"MARK".repeat(limits::INTERNAL_MATCHES + 1),
        Coverage::Full,
    );
    assert_eq!(result.status, Status::Inconclusive);
    assert!(result.matches.is_empty());
    assert!(!result.coverage_complete);
}

#[test]
fn reporting_limit_preserves_completeness_and_marks_omitted_evidence() {
    let rules = (0..limits::MATCHING_RULES + 3)
        .map(|n| format!("rule r{n} {{ condition: true }}\n"))
        .collect::<String>();
    let session = CompiledSession::compile(rules.as_bytes()).unwrap();
    let result = session.scan_bytes(b"owned", Coverage::Full);
    assert_eq!(result.status, Status::Partial);
    assert!(result.matches.is_empty());
    assert!(result.reporting_truncated);
    assert!(!result.coverage_complete);
}

#[test]
fn readonly_fd_range_is_owned_and_truncation_pipe_and_writable_fds_fail_closed() {
    let path = std::env::temp_dir().join(format!("foxhole-yara-owned-{}", std::process::id()));
    let mut writable = std::fs::File::create(&path).unwrap();
    writable
        .write_all(b"prefixFOXHOLE_BENIGN_MARKERsuffix")
        .unwrap();
    let session = CompiledSession::compile(MARKER).unwrap();
    assert_eq!(
        session
            .scan_fd(writable.as_raw_fd(), 6, 21, Coverage::Full)
            .status,
        Status::Unsupported
    );
    let read = std::fs::File::open(&path).unwrap();
    assert_eq!(
        session
            .scan_fd(read.as_raw_fd(), 6, 21, Coverage::Full)
            .matches
            .len(),
        1
    );
    assert_eq!(
        session
            .scan_fd(read.as_raw_fd(), 6, 100, Coverage::Full)
            .status,
        Status::Partial
    );
    assert_eq!(
        session
            .scan_fd(read.as_raw_fd(), u64::MAX, 2, Coverage::Full)
            .status,
        Status::Error
    );
    unsafe {
        let mut fds = [0; 2];
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        assert_eq!(
            session.scan_fd(fds[0], 0, 1, Coverage::Full).status,
            Status::Unsupported
        );
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn cancellation_is_a_publication_fence_and_requires_process_settlement() {
    let session = CompiledSession::compile(MARKER).unwrap();
    session.request_cancel();
    let result = session.scan_bytes(b"FOXHOLE_BENIGN_MARKER", Coverage::Full);
    assert_eq!(result.status, Status::Cancelled);
    assert!(result.matches.is_empty());
    assert!(!result.coverage_complete);
    assert!(!session.cancellation_interrupts_native());
}

#[test]
fn selected_dex_and_hash_modules_compile_and_only_scan_static_bytes() {
    let session = CompiledSession::compile(br#"import "dex" import "hash" rule not_dex { condition: not dex.is_dex and hash.sha256(0, filesize) != "" }"#).unwrap();
    let result = session.scan_bytes(b"benign ordinary bytes", Coverage::Full);
    assert_eq!(result.status, Status::Complete);
    assert_eq!(result.matches[0].rule_id, "not_dex");
}

#[test]
fn fast_scan_preserves_required_count_second_offset_and_second_length() {
    let counts = CompiledSession::compile(br#"rule ge_two { strings: $marker = "MARK" condition: #marker >= 2 } rule exactly_two { strings: $marker = "MARK" condition: #marker == 2 }"#).unwrap();
    let two = counts.scan_bytes(b"MARK__MARK", Coverage::Full);
    assert_eq!(two.status, Status::Complete);
    assert_eq!(two.matches.len(), 2);
    let three = counts.scan_bytes(b"MARK__MARK__MARK", Coverage::Full);
    assert_eq!(three.status, Status::Complete);
    assert_eq!(
        three
            .matches
            .iter()
            .map(|r| r.rule_id.as_str())
            .collect::<Vec<_>>(),
        vec!["ge_two"]
    );
    assert!(three.matches[0].patterns[0].offsets.len() >= 2);
    let offset = CompiledSession::compile(
        br#"rule second { strings: $marker = "MARK" condition: @marker[2] == 6 }"#,
    )
    .unwrap();
    let report = offset.scan_bytes(b"MARK__MARK__MARK", Coverage::Full);
    assert_eq!(report.status, Status::Complete);
    assert_eq!(report.matches[0].patterns[0].offsets[1].start, 6);
    let length = CompiledSession::compile(
        br#"rule second_length { strings: $marker = /MARK[0-9]+/ condition: !marker[2] == 6 }"#,
    )
    .unwrap();
    let report = length.scan_bytes(b"MARK1__MARK22__MARK333", Coverage::Full);
    assert_eq!(report.status, Status::Complete);
    assert_eq!(report.matches[0].patterns[0].offsets[1].length, 6);
}

#[test]
fn private_count_rule_controls_public_rule_without_losing_semantics() {
    let session = CompiledSession::compile(br#"private rule hidden { strings: $marker = "MARK" private condition: #marker == 2 } rule visible { condition: hidden }"#).unwrap();
    let two = session.scan_bytes(b"MARK__MARK", Coverage::Full);
    assert_eq!(two.status, Status::Complete);
    assert_eq!(two.matches[0].rule_id, "visible");
    let three = session.scan_bytes(b"MARK__MARK__MARK", Coverage::Full);
    assert_eq!(three.status, Status::Complete);
    assert!(three.matches.is_empty());
}

#[test]
fn hex_literal_and_private_identifier_budgets_reject_before_compilation() {
    let hex = format!(
        "rule x {{ strings: $a = {{ {} }} condition: $a }}",
        "41 ".repeat(limits::LITERAL_BYTES / 3 + 1)
    );
    assert_eq!(
        CompiledSession::compile(hex.as_bytes()).unwrap_err().reason,
        "literal_limit"
    );
    let name = format!(
        "rule x {{ strings: ${} = \"MARK\" private condition: any of them }}",
        "a".repeat(limits::IDENTIFIER_BYTES)
    );
    assert_eq!(
        CompiledSession::compile(name.as_bytes())
            .unwrap_err()
            .reason,
        "identifier_limit"
    );
}

#[test]
fn private_and_global_rule_iterator_lengths_match_the_actual_items() {
    for source in [
        "private rule hidden { condition: false } rule shown { condition: hidden }",
        "private rule hidden { condition: true } rule shown { condition: hidden }",
        "global rule gate { condition: false } private rule hidden { condition: true } rule shown { condition: hidden }",
    ] {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source).unwrap();
        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(b"owned").unwrap();
        for include_private in [false, true] {
            let matching = results.matching_rules().include_private(include_private);
            let expected = matching.len();
            assert_eq!(expected, matching.count());
            let nonmatching = results
                .non_matching_rules()
                .include_private(include_private);
            let expected = nonmatching.len();
            assert_eq!(expected, nonmatching.count());
        }
    }
}
