use std::fs;
use std::path::Path;
use yara_x_parser::ast::AST;

#[test]
fn ast_debug_matches_all_published_parser_fixtures() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor/yara-x-parser/src/parser/tests/testdata");
    let mut checked = 0;
    for entry in fs::read_dir(fixtures).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("in") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        let actual = format!("{:?}", AST::from(source.as_str()));
        let expected = fs::read_to_string(path.with_extension("ast")).unwrap();
        assert_eq!(actual, expected, "fixture {}", path.display());
        checked += 1;
    }
    assert!(checked > 50, "the upstream fixture set must be present");
}
