use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

use foxcore_api::DnsCategory;
use foxcore_route::ruleset::compile_rule_set_artifact;

const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("foxcore-dns-compile: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse(env::args().skip(1))?;
    let source = fs::read(&options.input)
        .map_err(|error| format!("read {}: {error}", options.input.display()))?;
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err("input size must be in 1..=64 MiB".into());
    }
    let source_text =
        std::str::from_utf8(&source).map_err(|_| "input must be UTF-8".to_string())?;
    let mut block = BTreeSet::new();
    let mut allow = BTreeSet::new();
    for line in source_text.lines() {
        if let Some(rule) = parse_dns_rule(line) {
            match rule.action {
                RuleAction::Block => {
                    block.insert(rule.domain);
                }
                RuleAction::Allow => {
                    allow.insert(rule.domain);
                }
            }
        }
    }
    if let Some(path) = &options.allowlist {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            allow.insert(normalize_domain(line)?);
        }
    }
    // An exception always wins at lookup time. Removing it from the block map
    // also makes the artifact smaller and keeps its entry counts honest.
    block.retain(|domain| !allow.contains(domain));
    if block.is_empty() {
        return Err("input produced no supported DNS suffix rules".into());
    }
    let block: Vec<String> = block.into_iter().collect();
    let allow: Vec<String> = allow.into_iter().collect();
    let compiled = compile_rule_set_artifact(&source, &block, &allow, Some(options.category))
        .map_err(|error| error.to_string())?;
    if let Some(parent) = options.output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(&options.output, &compiled.bytes)
        .map_err(|error| format!("write {}: {error}", options.output.display()))?;
    eprintln!(
        "compiled {} block and {} allow suffixes into {} bytes",
        compiled.block_entries,
        compiled.allow_entries,
        compiled.bytes.len()
    );
    Ok(())
}

#[derive(Debug)]
struct Options {
    input: PathBuf,
    output: PathBuf,
    allowlist: Option<PathBuf>,
    category: DnsCategory,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut input = None;
        let mut output = None;
        let mut allowlist = None;
        let mut category = DnsCategory::Ads;
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            let value = |arguments: &mut std::iter::Peekable<_>, name: &str| {
                arguments
                    .next()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match argument.as_str() {
                "--input" => input = Some(PathBuf::from(value(&mut arguments, "--input")?)),
                "--output" => output = Some(PathBuf::from(value(&mut arguments, "--output")?)),
                "--allowlist" => {
                    allowlist = Some(PathBuf::from(value(&mut arguments, "--allowlist")?));
                }
                "--category" => {
                    category = parse_category(&value(&mut arguments, "--category")?)?;
                }
                "--help" | "-h" => {
                    return Err("usage: foxcore-dns-compile --input FILE --output FILE \
                         [--allowlist FILE] [--category ads|trackers|telemetry|malicious]"
                        .into());
                }
                _ => return Err(format!("unknown argument: {argument}")),
            }
        }
        Ok(Self {
            input: input.ok_or_else(|| "--input is required".to_string())?,
            output: output.ok_or_else(|| "--output is required".to_string())?,
            allowlist,
            category,
        })
    }
}

fn parse_category(value: &str) -> Result<DnsCategory, String> {
    match value {
        "ads" => Ok(DnsCategory::Ads),
        "trackers" => Ok(DnsCategory::Trackers),
        "telemetry" => Ok(DnsCategory::Telemetry),
        "malicious" => Ok(DnsCategory::Malicious),
        _ => Err(format!("unsupported category: {value}")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRule {
    action: RuleAction,
    domain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Block,
    Allow,
}

fn parse_dns_rule(line: &str) -> Option<ParsedRule> {
    let mut line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return None;
    }
    let action = if let Some(rule) = line.strip_prefix("@@") {
        line = rule;
        RuleAction::Allow
    } else {
        RuleAction::Block
    };
    let anchored = line.strip_prefix("||")?;
    let domain_end = anchored.find(['^', '$', '|']).unwrap_or(anchored.len());
    let domain = anchored[..domain_end].trim_matches('.');
    if domain.is_empty() || domain.contains('*') || domain.contains('/') || domain.contains(':') {
        return None;
    }
    let modifiers = anchored[domain_end..]
        .split_once('$')
        .map(|(_, value)| value)
        .unwrap_or_default();
    if !supported_modifiers(modifiers) {
        return None;
    }
    normalize_domain(domain)
        .ok()
        .map(|domain| ParsedRule { action, domain })
}

/// Only modifiers this compiler can represent without changing what a rule
/// means. Anything else drops the rule, which is the safe direction: a rule that
/// is not compiled blocks nothing, while a rule compiled with the wrong meaning
/// unblocks something.
///
/// `$badfilter` is the reason this is worth spelling out. In AdGuard it disables
/// *one specific identical rule* in another list — it is not an exception, and
/// it is scoped to the rule it names. Compiled here it became a plain allow
/// entry, and allow entries are checked ahead of every artifact in the set, so a
/// single `||evil.example^$badfilter` line anywhere in any upstream list lifted
/// that name out of every rule set the device had, Malicious included. An
/// upstream author who never intended a global exception could ship one, which
/// is exactly the shape a supply-chain edit would take. FoxCore does not track
/// rules by identity across lists, so the modifier cannot be honoured; the rule
/// is therefore dropped rather than reinterpreted.
fn supported_modifiers(modifiers: &str) -> bool {
    modifiers.is_empty()
        || modifiers
            .split(',')
            .all(|modifier| modifier.eq_ignore_ascii_case("important"))
}

fn normalize_domain(value: &str) -> Result<String, String> {
    let domain = value
        .trim()
        .trim_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        })
    {
        return Err("allowlist contains an invalid DNS name".into());
    }
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_losslessly_representable_dns_rules() {
        assert_eq!(
            parse_dns_rule("||Ads.Example^$important"),
            Some(ParsedRule {
                action: RuleAction::Block,
                domain: "ads.example".into(),
            })
        );
        assert_eq!(
            parse_dns_rule("@@||safe.example^"),
            Some(ParsedRule {
                action: RuleAction::Allow,
                domain: "safe.example".into(),
            })
        );
        assert!(parse_dns_rule("||context.example^$third-party").is_none());
        assert!(parse_dns_rule("/tracker/").is_none());
    }

    /// `$badfilter` disables one identical rule in another list. It is not an
    /// exception, and compiling it as one turned a line an upstream author could
    /// add for their own list into a global unblock: allow entries are consulted
    /// ahead of every artifact, so `||evil.example^$badfilter` anywhere lifted
    /// that name out of every rule set on the device, Malicious included.
    ///
    /// Nothing here tracks rules by identity across lists, so the modifier
    /// cannot be honoured. Dropping the rule is the only reading that is not a
    /// lie in one direction or the other.
    #[test]
    fn a_badfilter_rule_is_dropped_rather_than_compiled_into_a_global_exception() {
        assert_eq!(parse_dns_rule("||disabled.example^$badfilter"), None);
        assert_eq!(parse_dns_rule("||disabled.example^$BadFilter"), None);
        assert_eq!(
            parse_dns_rule("||disabled.example^$important,badfilter"),
            None,
            "a modifier list is unsupported as soon as one member is"
        );
        assert_eq!(
            parse_dns_rule("@@||disabled.example^$badfilter"),
            None,
            "an exception carrying it is dropped too: the modifier is what is \
             unsupported, not the action it happened to sit on"
        );
    }

    #[test]
    fn rejects_ambiguous_or_non_dns_names() {
        assert!(parse_dns_rule("||*.example^").is_none());
        assert!(parse_dns_rule("||https://example.test^").is_none());
        assert!(parse_dns_rule("example.test").is_none());
    }
}
