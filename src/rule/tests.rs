use super::*;
use std::fs;

fn schema() -> Arc<Schema> {
    let mut s = Schema::default();
    s.add("ip", "cidr", false, false).unwrap();
    s.add("ua", "regex", true, false).unwrap();
    s.add("url", "regex", false, false).unwrap();
    Arc::new(s)
}

fn rules(text: &str) -> RuleSet {
    RuleSet::from_text(text, schema()).expect("parse")
}

/// Inputs for the test schema; `None` leaves a field unset.
fn check(set: &RuleSet, ip: Option<&str>, ua: Option<&str>, url: Option<&str>) -> Option<usize> {
    let s = set.schema();
    let inputs: Vec<Option<Input>> = [ip, ua, url]
        .iter()
        .enumerate()
        .map(|(i, v)| v.and_then(|v| s.input(i, v.as_bytes())))
        .collect();
    set.first_match(&inputs)
}

const BOTS: &str = "\
# Googlebot, API only
ip:  66.249.64.0/19
ua:  Googlebot
url: ^/api/

ip:  157.55.39.0/24
ua:  bingbot

ua:  Mozilla/5.0 \\(compatible; SomeBot 1\\.0\\)
url: ^/admin
";

#[test]
fn every_named_field_must_match() {
    let s = rules(BOTS);
    assert_eq!(s.len(), 3);
    assert_eq!(
        check(
            &s,
            Some("66.249.64.10"),
            Some("x Googlebot/2.1"),
            Some("/api/v1")
        ),
        Some(2)
    );
    // Right UA, wrong network.
    assert_eq!(
        check(&s, Some("10.0.0.1"), Some("Googlebot"), Some("/api/v1")),
        None
    );
    // Right network and UA, wrong URL.
    assert_eq!(
        check(&s, Some("66.249.64.10"), Some("Googlebot"), Some("/home")),
        None
    );
    // Paired, not independent: a Bingbot UA from a Google address is no match.
    assert_eq!(
        check(&s, Some("66.249.64.10"), Some("bingbot"), Some("/api/")),
        None
    );
}

#[test]
fn a_field_left_out_matches_anything() {
    let s = rules(BOTS);
    // The bingbot rule names no url.
    assert_eq!(
        check(&s, Some("157.55.39.1"), Some("bingbot"), Some("/whatever")),
        Some(6)
    );
    assert_eq!(
        check(&s, Some("157.55.39.1"), Some("bingbot"), None),
        Some(6)
    );
    // The SomeBot rule names no ip, and its value has spaces, parens and a ';'.
    assert_eq!(
        check(
            &s,
            Some("1.2.3.4"),
            Some("Mozilla/5.0 (compatible; SomeBot 1.0)"),
            Some("/admin/x")
        ),
        Some(9)
    );
    assert_eq!(
        check(
            &s,
            None,
            Some("Mozilla/5.0 (compatible; SomeBot 1.0)"),
            Some("/admin/x")
        ),
        Some(9)
    );
}

#[test]
fn an_unset_field_only_matches_rules_that_leave_it_out() {
    let s = rules(BOTS);
    assert_eq!(check(&s, None, Some("bingbot"), None), None);
    assert_eq!(check(&s, Some("157.55.39.1"), None, None), None);
    assert_eq!(check(&s, None, None, None), None);
}

#[test]
fn unparseable_address_counts_as_unset() {
    let s = rules(BOTS);
    assert_eq!(check(&s, Some("not-an-ip"), Some("bingbot"), None), None);
}

#[test]
fn first_match_is_in_file_order() {
    let s = rules("ua: bot\n\nua: Googlebot\n\nip: 0.0.0.0/0\n");
    assert_eq!(check(&s, Some("1.1.1.1"), Some("Googlebot"), None), Some(1));
    assert_eq!(check(&s, Some("1.1.1.1"), Some("x"), None), Some(5));
}

#[test]
fn case_insensitive_is_per_field() {
    let s = rules("ua: googlebot\n\nurl: ^/API\n");
    assert_eq!(check(&s, None, Some("GoogleBot"), None), Some(1));
    assert_eq!(check(&s, None, None, Some("/api")), None);
    assert_eq!(check(&s, None, None, Some("/API")), Some(3));
}

#[test]
fn ipv6_values_and_mapped_ipv4_clients() {
    let s = rules("ip: 2001:db8::/32\n\nip: 10.0.0.0/8\n");
    assert_eq!(check(&s, Some("2001:db8::1"), None, None), Some(1));
    assert_eq!(check(&s, Some("::ffff:10.1.2.3"), None, None), Some(3));
    assert_eq!(check(&s, Some("2001:db9::1"), None, None), None);
}

#[test]
fn shared_prefix_and_overlapping_buckets() {
    // Two rules on one prefix, and a wider prefix covering both.
    let s = rules("ip: 10.0.0.0/8\nua: a\n\nip: 10.0.0.0/8\nua: b\n\nip: 10.1.0.0/16\nua: c\n");
    assert_eq!(check(&s, Some("10.1.2.3"), Some("b"), None), Some(4));
    assert_eq!(check(&s, Some("10.1.2.3"), Some("c"), None), Some(7));
    assert_eq!(check(&s, Some("10.2.0.1"), Some("c"), None), None);
}

#[test]
fn comments_do_not_end_a_rule_but_blank_lines_do() {
    let s = rules("# header\n  ip: 10.0.0.0/8\n  # note\n  ua: x\n\n\n# trailing\n");
    assert_eq!(s.len(), 1);
    assert_eq!(check(&s, Some("10.0.0.1"), Some("x"), None), Some(2));
}

#[test]
fn hash_and_colon_inside_a_value_are_kept() {
    let s = rules(r"url: ^/docs\#a:b$");
    assert_eq!(check(&s, None, None, Some("/docs#a:b")), Some(1));
}

#[test]
fn many_rules_cross_word_boundaries() {
    let text: String = (0..200).map(|i| format!("ua: ^bot-{i}$\n\n")).collect();
    let s = rules(&text);
    assert_eq!(s.len(), 200);
    assert_eq!(check(&s, None, Some("bot-130"), None), Some(130 * 2 + 1));
    assert_eq!(check(&s, None, Some("bot-200"), None), None);
}

#[test]
fn matches_across_regex_chunks() {
    // Enough rules for several chunks, with the hit in the last one, and an ip
    // column narrowing the candidates so earlier chunks are skipped.
    let n = REGEX_CHUNK * 2 + 10;
    let text: String = (0..n)
        .map(|i| format!("ip: 10.{}.{}.0/24\nua: ^bot-{i}$\n\n", i / 256, i % 256))
        .collect();
    let s = rules(&text);
    let last = n - 1;
    let ip = format!("10.{}.{}.1", last / 256, last % 256);
    assert_eq!(
        check(&s, Some(&ip), Some(&format!("bot-{last}")), None),
        Some(last * 3 + 1)
    );
    // Same UA from the first rule's network: the fields are still paired.
    assert_eq!(
        check(&s, Some("10.0.0.1"), Some(&format!("bot-{last}")), None),
        None
    );
    assert_eq!(check(&s, Some("10.0.0.1"), Some("bot-0"), None), Some(1));
}

#[test]
fn line_errors_name_the_line() {
    let cases = [
        (
            "ip: 10.0.0.0/8\nbroken\n",
            2,
            "line 2: expected \"field: value\"",
        ),
        ("host: example.com\n", 1, "line 1: unknown field \"host\""),
        (
            "ua: a\nua: b\n",
            2,
            "line 2: field \"ua\" appears twice in one rule",
        ),
        ("ua:\n", 1, "line 1: field \"ua\" has an empty value"),
        ("\nip: nope\n", 2, "line 2: invalid IP address \"nope\""),
    ];
    for (text, line, msg) in cases {
        let err = RuleSet::from_text(text, schema()).unwrap_err();
        assert!(
            matches!(err, RuleError::Line { line: l, .. } if l == line),
            "{text:?}: {err:?}"
        );
        assert_eq!(err.to_string(), msg);
    }
}

#[test]
fn bad_regex_names_the_line() {
    let err = RuleSet::from_text("ua: ok\n\nurl: [unclosed\n", schema()).unwrap_err();
    assert!(
        matches!(
            &err,
            RuleError::Pattern(PatternError::Pattern { line: 3, .. })
        ),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with(r#"line 3: invalid pattern "[unclosed": "#)
    );
}

#[test]
fn no_fields_is_an_error() {
    let err = RuleSet::from_text("", Arc::new(Schema::default())).unwrap_err();
    assert!(matches!(err, RuleError::NoFields));
}

#[test]
fn empty_file_matches_nothing() {
    let s = rules("# nothing\n\n");
    assert!(s.is_empty());
    assert_eq!(check(&s, Some("10.0.0.1"), Some("x"), Some("/")), None);
}

#[test]
fn required_fields_must_appear_in_every_rule() {
    let mut s = Schema::default();
    s.add("ip", "cidr", false, true).unwrap();
    s.add("ua", "regex", false, false).unwrap();
    let s = Arc::new(s);

    let ok = RuleSet::from_text("ip: 10.0.0.0/8\nua: a\n\nip: 10.0.0.0/8\n", s.clone());
    assert_eq!(ok.expect("parse").len(), 2);

    // Reported at the block's first line, for the middle block and the last one.
    for (text, line) in [
        ("ip: 10.0.0.0/8\n\n# note\nua: a\n\nip: 1.2.3.4\n", 4),
        ("ip: 10.0.0.0/8\n\nua: a\n", 3),
    ] {
        let err = RuleSet::from_text(text, s.clone()).unwrap_err();
        assert!(
            matches!(err, RuleError::Line { line: l, .. } if l == line),
            "{text:?}: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("line {line}: rule is missing required field \"ip\"")
        );
    }
}

#[test]
fn missing_file_is_an_error_unless_allowed() {
    let path = Path::new("/nonexistent/memstore/rules");
    let err = RuleSet::from_file(path, schema(), false).unwrap_err();
    assert!(matches!(err, RuleError::Read(_)), "{err:?}");
    let s = RuleSet::from_file(path, schema(), true).expect("tolerated");
    assert!(s.is_empty());
}

#[test]
fn reads_from_a_file() {
    let dir = std::env::temp_dir().join(format!("vmod_rule_test_{}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("bots.rules");
    fs::write(&path, BOTS).expect("write");
    assert_eq!(
        RuleSet::from_file(&path, schema(), false)
            .expect("load")
            .len(),
        3
    );
    fs::remove_dir_all(&dir).ok();
}
