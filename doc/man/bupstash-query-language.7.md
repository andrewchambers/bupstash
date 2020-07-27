bupstash-query-language(7)
==========================

## SYNOPSIS

Description of the bupstash query language used by bupstash-get(1), bupstash-list(1) and bupstash-rm(1).

## DESCRIPTION

The bupstash query language is used to filter and select items from a bupstash repository. Check 
the examples section for practical uses, or read the language section for a more precise description.

## EXAMPLES

Glob matching:
```
$ bupstash list name=*.tar
... name=foo.tar
... name=bar.tar
```

Literal matching:
```
$ bupstash list name==*.tar
...
```

And conditions matching:
```
$ bupstash list type=backup and [hostname=server1 or hostname=server2]
...
```

Quoting:

```
$ bupstash rm name="my files.tar"
```

## LANGUAGE

### Tags and values

A tag name is a string containg a set of characters matching the regular
expression ```[A-Za-z0-9-_]+```.

A values is a set of any characters except a delimiter.

### DELIMITERS

As queries may span multiple command line arguments, the gap between arguments is treated as a special
delimiting character for the sake of query parsing.

### GLOBBING

Some operators accept a glob to match against, the following describes the valid globbing meta characters.

```
    ? matches any single character.

    * matches any (possibly empty) sequence of characters.

    ** matches the current directory and arbitrary subdirectories. This sequence must form a single path component, so both **a and b** are invalid and will result in an error. A sequence of more than two consecutive * characters is also invalid.

    [...] matches any character inside the brackets. Character sequences can also specify ranges of characters, as ordered by Unicode, so e.g. [0-9] specifies any character between 0 and 9 inclusive. An unclosed bracket is invalid.

    [!...] is the negation of [...], i.e. it matches any characters not in the brackets.

    The metacharacters ?, *, [, ] can be matched by using brackets (e.g. [?]). When a ] occurs immediately following [ or [! then it is interpreted as being part of, rather then ending, the character set, so ] and NOT ] can be matched by []] and [!]] respectively. The - character can be specified inside a character sequence pattern by placing it at the start or the end, e.g. [abc-].
```

(Documentation taken from the underlying [software library](https://docs.rs/glob/0.3.0/glob/struct.Pattern.html)).


### BINARY OPERATORS

Check a tag matches a glob:

```
TAGNAME = GLOB
```

Check a tag matches an literal value.

```
TAGNAME == VALUE
```

Check a tag does not match a glob.

```
TAG ~= GLOB
```

Check a tag does not match a literal value.

```
TAG ~== VALUE
```

### UNARY OPERATORS

Invert an expression.

```
~ EXPR
```

Match if either expression matches.
```
EXPR or EXPR
```

Match if both expressions match.

```
EXPR and EXPR
```

### GROUPING

Use brackets to alter the default precedence.
```
[ EXPR ]
```

Note, This differs from the typical tradition of using `()` for grouping so queries are
easier to write in shell scripts where `()` already has design a designated meaning.

## SEE ALSO

bupstash(1), bupstash-put(1), bupstash-list(1), bupstash-rm(1)
