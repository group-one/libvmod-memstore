# Example regex file for memstore.regex_set()
#
# One pattern per line, in Rust regex syntax:
#   https://docs.rs/regex/latest/regex/#syntax
#
# Matching is unanchored, like VCL's `~`: the pattern has to be found *in* the
# subject, not to cover all of it. Use ^ and $ when that matters.
#
# Blank lines are ignored. `#` starts a comment only at the *beginning* of a
# line, because `#` is a legal regex character -- there are no trailing
# comments here. Lines are trimmed, so a significant leading or trailing space
# has to be written as \s, [ ] or \x20.
#
# This file is meant for User-Agent matching, so load it case-insensitively:
#   new bots = memstore.regex_set("/etc/varnish/bots.re", case_insensitive = true);
# An inline (?i) works per pattern regardless of that setting.

# Well-behaved search crawlers
(?:Googlebot|bingbot|DuckDuckBot|YandexBot)/

# Command-line fetchers, anchored at the start of the User-Agent
^(?:curl|Wget|python-requests|Go-http-client)/

# Headless browsers
HeadlessChrome|PhantomJS|Puppeteer

# Scanners and mirroring tools
(?:nikto|sqlmap|masscan|zgrab|HTTrack)

# An empty or single-character User-Agent is almost never a real browser
^.?$
