# libvmod-memstore

A [Varnish](https://github.com/varnish/varnish) VMOD, providing four
instantiable storage objects:

| Object | Purpose |
| --- | --- |
| `cidr_set` | A bucketed set of IPv4/IPv6 CIDR prefixes, loaded from a line-based file, with an IP-containment test and runtime reload. |
| `kv_store` | A string key/value store, loaded from a line-based file, with add/update/delete and runtime reload. |
| `regex_set` | A list of regular expressions, loaded from a line-based file, matched as one set, with runtime reload. |
| `rule_set` | Rules over fields the VCL declares (CIDR or regex), loaded from a block-based file and matched against values set per request, with runtime reload. |

All four are ordinary VCL objects, so a VCL can declare as many independent instances as
it needs.

The full, always-current VCL API reference is [`API.md`](API.md), generated from the source
on every build.

## Quick start

```vcl
import memstore;

sub vcl_init {
    # Fails if file is missing
    new trusted   = memstore.cidr_set("/etc/varnish/trusted.cidrs");
    # Returns an empty list if file is missing
    new redirects = memstore.kv_store("/etc/varnish/redirects.txt", allow_missing = true);
    new bots      = memstore.regex_set("/etc/varnish/bots.re", case_insensitive = true);

    # Rules over fields you declare; each rule must match on every field it names.
    new access = memstore.rule_set("/etc/varnish/access.rules");
    access.field("ip",  "cidr");
    access.field("ua",  "regex", case_insensitive = true);
    access.field("url", "regex");
    access.load();
}

sub vcl_recv {
    if (!trusted.contains(client.ip)) {
        return (synth(403, "Forbidden"));
    }

    if (bots.matches(req.http.User-Agent)) {
        # which() reports the pattern that fired, which is what you want in the log.
        std.log("bot: " + bots.which(req.http.User-Agent));
        set req.http.X-Bot = "1";
    }

    if (redirects.exists(req.url)) {
        set req.http.X-Redirect-To = redirects.get(req.url);
        return (synth(301, "Moved"));
    }

    access.set("ip",  client.ip);
    access.set("ua",  req.http.User-Agent);
    access.set("url", req.url);
    if (access.matches()) {
        # which() is the line the matching rule starts on.
        std.log("access rule at line " + access.which());
        return (synth(403, "Forbidden"));
    }
}
```

See [`examples/`](examples/) for sample data files.

### Varnish ABI

This module has only been built and tested against the latest trunk of [varnish](https://github.com/varnish/varnish)

## File formats

### `cidr_set`

One entry per line, `ADDRESS` or `ADDRESS/PREFIXLEN`. A bare address is a host route
(`/32`, `/128`). IPv4 and IPv6 may be mixed. Blank lines are ignored; `#` and `//` start a
comment.

```
10.0.0.0/8
192.168.1.0/24
127.0.0.1
2001:db8::/32
```

### `kv_store`

One `key<separator>value` pair per line; the separator defaults to `=` and is configurable
per instance. Only the **first** occurrence splits the line, so values may contain it. Keys
and values are trimmed. Blank lines are ignored, and `#` starts a comment only at the
beginning of a line.

```
/old-page = /new-page
url       = https://example.com/?a=1&b=2
```

### `regex_set`

One pattern per line, in [Rust regex syntax](https://docs.rs/regex/latest/regex/#syntax).
Blank lines are ignored, and `#` starts a comment only at the **beginning** of a line —
`#` is a legal regex character, so there are no trailing comments here. Lines are trimmed,
so a significant leading or trailing space must be written `\s`, `[ ]` or `\x20`.
`case_insensitive` is a constructor argument and applies to the whole instance; an inline
`(?i)` works per pattern regardless.

```
^(?:curl|Wget)/
(?:Googlebot|bingbot)/
\.php$
```

### `rule_set`

One rule per block of `field: value` lines; blank lines separate blocks. The field names
are the ones the VCL declared with `field()`. Only the **first** `:` splits a line, so values
may contain spaces, colons (IPv6) and `#`. Names and values are trimmed. `#` starts a
comment only at the beginning of a line, and a comment does not end a block.

A rule matches when every field it names matches the value given with `set()`. A field the
block leaves out matches anything, including no value at all -- unless the field was
declared with `required = true`, in which case every block must name it or the load fails.
`cidr` values are prefixes as in `cidr_set`, and `regex` values are patterns as in
`regex_set`. Escape regex metacharacters such as `(` `)` `.` when you mean them literally.

```
# Googlebot, API only
ip:  66.249.64.0/19
ua:  Googlebot
url: ^/api/

ip:  157.55.39.0/24
ua:  bingbot

ua:  Mozilla/5.0 \(compatible; SomeBot 1\.0\)
url: ^/admin
```
