bupstash-query-language(7)
==========================

## SYNOPSIS

The bupstash query language used by bupstash commands.

## DESCRIPTION

The bupstash query language is used to filter and select items from a bupstash repository. Check 
the examples section for practical uses, or read the language section for a more precise description.

## EXAMPLES

Glob matching:
```
$ bupstash list name="*.tar"
... name=foo.tar
... name=bar.tar
```

Literal matching:
```
$ bupstash list name=="*.tar"
...
```

Age based matching:

```
$ bupstash list newer-than "1 month"
$ bupstash list older-than 2d
$ bupstash list older-than 1y
...
```

And condition matching:
```
$ bupstash list type=backup and hostname=server1 hostname=server2
...
```

Or condition matching:
```
$ bupstash list hostname=server1 or hostname=server2
...
```

Precedence grouping:
```
$ bupstash list [ hostname=server1 or hostname=server2 ] and date=2020-* 
...
```

Quote using your shell's builtin quoting:

```
$ bupstash rm name="my files.tar"
```

## LANGUAGE

### Delimiters

As queries may span multiple command line arguments, the gap between arguments is treated as a special
delimiting character for the sake of query parsing.

### Tags and values

A tag name is a string containg a set of characters matching the regular
expression ```[A-Za-z0-9-_]+```.

A values is a set of any characters except a delimiter.

### Durations

A duration is a concatenation of time spans, where each time span is an integer number and a suffix.

Supported suffixes:

- seconds, second, sec, s
- minutes, minute, min, m
- hours, hour, hr, h
- days, day, d
- weeks, week, w
- months, month, M -- defined as 30.44 days
- years, year, y -- defined as 365.25 days

### Globbing

Some operators accept a glob to match against, the following describes the valid globbing meta characters.

```
    ? matches any single character. (If the literal_separator option is enabled, then ? can never match a path separator.)
    * matches zero or more characters. (If the literal_separator option is enabled, then * can never match a path separator.)
    ** recursively matches directories but are only legal in three situations. First, if the glob starts with **/, then it matches all directories. For example, **/foo matches foo and bar/foo but not foo/bar. Secondly, if the glob ends with /**, then it matches all sub-entries. For example, foo/** matches foo/a and foo/a/b, but not foo. Thirdly, if the glob contains /**/ anywhere within the pattern, then it matches zero or more directories. Using ** anywhere else is illegal (N.B. the glob ** is allowed and means “match everything”).
    {a,b} matches a or b where a and b are arbitrary glob patterns. (N.B. Nesting {...} is not currently allowed.)
    [ab] matches a or b where a and b are characters. Use [!ab] to match any character except for a and b.
    Metacharacters such as * and ? can be escaped with character class notation. e.g., [*] matches *.
    When backslash escapes are enabled, a backslash (\) will escape all meta characters in a glob. If it precedes a non-meta character, then the slash is ignored. A \\ will match a literal \\. Note that this mode is only enabled on Unix platforms by default, but can be enabled on any platform via the backslash_escape setting on Glob.
```

(Documentation taken from the underlying [glob software library](https://docs.rs/globset/0.4.8/globset/index.html#)).

### Binary operators

Check a tag matches a glob:

```
TAGNAME = GLOB
```

Check a tag matches a literal value.

```
TAGNAME == VALUE
```

Match if either expression matches.

```
EXPR or EXPR
```

Match if both expressions match.

```
EXPR and EXPR
```

### Age matching

```
older-than DURATION
newer-than DURATION
```

Take care that system clocks are configured correctly on both the querying machine, and devices sending backups, as incorrect
system clocks could cause accidental removal of items.

### Unary operators

Invert an expression.

```
~ EXPR
```


### grouping

Use brackets to alter the default precedence.

```
[ EXPR ]
```

Note, This differs from the typical tradition of using `()` for grouping so queries are
easier to write in shell scripts where `()` already has a designated meaning.

## SEE ALSO

bupstash(1), bupstash-put(1), bupstash-list(1), bupstash-rm(1)
