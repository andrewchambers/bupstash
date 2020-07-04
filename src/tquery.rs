use failure::Fail;
use std::collections::BTreeMap;

#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ParseError {
    #[fail(display = "syntax error, {}", msg)]
    SyntaxError {
        query: String,
        msg: String,
        span: (usize, usize),
    },
}

#[derive(Eq, PartialEq, Debug)]
pub enum Binop {
    And,
    Or,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Unop {
    Not,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Query {
    ExistsAssertion {
        tag: String,
        span: (usize, usize),
    },
    Glob {
        tag: String,
        pattern: glob::Pattern,
        span: (usize, usize),
    },
    Unop {
        op: Unop,
        span: (usize, usize),
        query: Box<Query>,
    },
    Binop {
        op: Binop,
        span: (usize, usize),
        left: Box<Query>,
        right: Box<Query>,
    },
}

fn is_ws(c: char) -> bool {
    match c {
        ' ' | '\t' | '\n' => true,
        _ => false,
    }
}

fn is_sep(c: char) -> bool {
    c == '•' || c == ';' || c == '\0'
}

fn is_value_char(c: char) -> bool {
    if is_sep(c) {
        return false;
    }
    match c {
        '~' | '=' | '(' | ')' => false,
        _ => true,
    }
}

macro_rules! impl_binop {
    ($name:ident, $opi:ident, $ops:literal , $sub:ident) => {
        fn $name(&mut self) -> Result<Query, ParseError> {
            let op = $ops;
            let mut l: Query;
            self.skip_insignificant();
            let (_, start_pos) = self.peek();
            l = self.$sub()?;
            loop {
                self.skip_insignificant();
                if !self.lookahead_with_ws_or_sep(op) {
                    return Ok(l);
                }
                self.advance(op.len() + 1);
                self.skip_insignificant();

                if self.is_eof() {
                    return Err(ParseError::SyntaxError {
                        query: self.query_chars.iter().collect(),
                        msg: format!("operator '{}' expects a value", op),
                        span: (self.offset - 1, self.offset - 1),
                    });
                }
                let r = self.$sub()?;
                let (_, end_pos) = self.peek();
                l = Query::Binop {
                    op: Binop::$opi,
                    span: (start_pos, end_pos),
                    left: Box::new(l),
                    right: Box::new(r),
                }
            }
        }
    };
}

struct Parser {
    query_chars: Vec<char>,
    offset: usize,
}

impl Parser {
    fn peek(&mut self) -> (char, usize) {
        match self.query_chars.get(self.offset) {
            Some(c) => (*c, self.offset),
            None => ('\0', self.offset),
        }
    }

    fn advance(&mut self, count: usize) {
        self.offset += count;
        if self.offset > self.query_chars.len() {
            self.offset = self.query_chars.len();
        }
    }

    fn get(&mut self) -> (char, usize) {
        let offset = self.offset;
        self.advance(1);
        match self.query_chars.get(offset) {
            Some(c) => (*c, offset),
            None => ('\0', offset),
        }
    }

    fn is_eof(&self) -> bool {
        self.offset == self.query_chars.len()
    }

    fn skip_insignificant(&mut self) {
        loop {
            if self.is_eof() {
                break;
            }
            let (c, _) = self.peek();
            if !is_ws(c) && !is_sep(c) {
                return;
            }
            self.advance(1);
        }
    }

    fn lookahead(&mut self, lookahead: &str) -> bool {
        for (i, c) in lookahead.chars().enumerate() {
            match self.query_chars.get(self.offset + i) {
                Some(gotc) if c == *gotc => (),
                _ => return false,
            }
        }
        true
    }

    fn consume_if_matches_maybe_sep(&mut self, s: &str) -> bool {
        if self.lookahead_with_ws_or_sep(s) {
            self.advance(s.len() + 1);
            true
        } else if self.lookahead(s) {
            self.advance(s.len());
            true
        } else {
            false
        }
    }

    fn lookahead_with_ws_or_sep(&mut self, op: &str) -> bool {
        if !self.lookahead(op) {
            return false;
        }
        match self.query_chars.get(self.offset + op.len()) {
            Some(c) => is_ws(*c) || is_sep(*c),
            _ => false,
        }
    }

    fn expect(&mut self, expected: &str) -> Result<(), ParseError> {
        if !self.lookahead(expected) {
            Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: format!("expected '{}'", expected),
                span: (self.offset, self.offset),
            })
        } else {
            self.advance(expected.len());
            Ok(())
        }
    }

    fn parse(&mut self) -> Result<Query, ParseError> {
        let v = self.parse_expr()?;

        self.skip_insignificant();

        if self.offset != self.query_chars.len() {
            return Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: "unexpected input at end of query'".to_owned(),
                span: (self.offset, self.offset),
            });
        }

        Ok(v)
    }

    fn parse_expr(&mut self) -> Result<Query, ParseError> {
        self.parse_and()
    }

    impl_binop!(parse_and, And, "and", parse_or);
    impl_binop!(parse_or, Or, "or", parse_base);

    fn parse_base(&mut self) -> Result<Query, ParseError> {
        self.skip_insignificant();
        let (c, _offset) = self.peek();
        if c == '(' {
            self.expect("(")?;
            let v = self.parse_expr()?;
            self.expect(")")?;
            Ok(v)
        } else if c == '~' {
            self.parse_unop()
        } else {
            self.parse_glob()
        }
    }

    fn parse_quoted_value(&mut self) -> Result<String, ParseError> {
        self.expect("\"")?;
        enum QuoteState {
            Start,
            Escape1,
            End,
        }

        let mut v = String::new();
        let mut st = QuoteState::Start;

        let (_, start_pos) = self.peek();
        loop {
            let (c, pos) = self.get();

            st = match (&st, c) {
                (QuoteState::Start, '"') => QuoteState::End,
                (QuoteState::Start, '\\') => QuoteState::Escape1,
                (QuoteState::Start, _) => {
                    v.push(c);
                    st
                }
                (QuoteState::Escape1, c) => {
                    v.push(c);
                    QuoteState::Start
                }
                (_, '\0') => {
                    return Err(ParseError::SyntaxError {
                        query: self.query_chars.iter().collect(),
                        msg: "unexpected end of input".to_string(),
                        span: (start_pos, pos),
                    })
                }
                (QuoteState::End, _) => panic!(),
            };

            if let QuoteState::End = st {
                break;
            }
        }

        Ok(v)
    }

    fn parse_value(&mut self) -> Result<String, ParseError> {
        let (c, pos) = self.peek();

        if c == '"' {
            return self.parse_quoted_value();
        }

        if !is_value_char(c) {
            return Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: "expected a value literal start character".to_string(),
                span: (pos, pos),
            });
        }
        self.get();

        let mut v = String::new();
        v.push(c);
        loop {
            match self.peek() {
                (c, _) if is_value_char(c) => {
                    self.advance(1);
                    v.push(c);
                }
                _ => break,
            }
        }

        Ok(v)
    }

    fn parse_glob(&mut self) -> Result<Query, ParseError> {
        self.skip_insignificant();
        let (_, tag_pos) = self.peek();
        let tag = self.parse_value()?;
        let (_, tag_end_pos) = self.peek();
        self.skip_insignificant();

        let escape: bool;

        if self.consume_if_matches_maybe_sep("==") {
            escape = true;
        } else if self.consume_if_matches_maybe_sep("=") {
            escape = false;
        } else {
            return Ok(Query::ExistsAssertion {
                tag,
                span: (tag_pos, tag_end_pos),
            });
        }

        let raw_pattern = self.parse_value()?;
        let (_, end_pos) = self.peek();

        let pattern = if escape {
            glob::Pattern::escape(&raw_pattern)
        } else {
            raw_pattern
        };

        let pattern = match glob::Pattern::new(&pattern) {
            Ok(pattern) => pattern,
            Err(err) => {
                return Err(ParseError::SyntaxError {
                    query: self.query_chars.iter().collect(),
                    msg: format!("invalid glob pattern: {}", err),
                    span: (tag_pos, end_pos),
                })
            }
        };

        Ok(Query::Glob {
            tag,
            pattern,
            span: (tag_pos, end_pos),
        })
    }

    fn parse_unop(&mut self) -> Result<Query, ParseError> {
        self.skip_insignificant();
        let (op, op_pos) = self.peek();
        self.skip_insignificant();

        let op = if self.consume_if_matches_maybe_sep("~") {
            Unop::Not
        } else {
            return Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: format!("unknown unary operator: {}", op),
                span: (op_pos, op_pos),
            });
        };

        let query = Box::new(self.parse_glob()?);
        let (_, end_pos) = self.peek();

        Ok(Query::Unop {
            op,
            query,
            span: (op_pos, end_pos),
        })
    }
}

pub fn parse(s: &str) -> Result<Query, ParseError> {
    let mut query_chars: Vec<char> = s.chars().collect();
    // Ensure the query always ends with a separator character,
    // this makes things more consistent.
    query_chars.push('•');

    let mut p = Parser {
        query_chars,
        offset: 0,
    };

    p.parse()
}

pub fn report_parse_error(e: ParseError) {
    match e {
        ParseError::SyntaxError { query, msg, span } => {
            let mut codemap = codemap::CodeMap::new();
            let indices: Vec<(usize, char)> = query.char_indices().collect();
            let query_span = codemap.add_file("<query>".to_owned(), query).span;
            let err_span = query_span.subspan(indices[span.0].0 as u64, indices[span.1].0 as u64);
            let label = codemap_diagnostic::SpanLabel {
                span: err_span,
                style: codemap_diagnostic::SpanStyle::Primary,
                label: None,
            };
            let d = codemap_diagnostic::Diagnostic {
                level: codemap_diagnostic::Level::Error,
                message: msg,
                code: None,
                spans: vec![label],
            };

            let mut emitter = codemap_diagnostic::Emitter::stderr(
                codemap_diagnostic::ColorConfig::Always,
                Some(&codemap),
            );
            emitter.emit(&[d]);
        }
    }
}

pub fn query_matches(q: &Query, tagset: &BTreeMap<String, Option<String>>) -> bool {
    match q {
        Query::Glob { tag, pattern, .. } => match tagset.get(tag) {
            Some(Some(v)) => pattern.matches(v),
            Some(None) => false,
            None => false,
        },
        Query::ExistsAssertion { tag, .. } => tagset.get(tag).is_some(),
        Query::Binop {
            op, left, right, ..
        } => match op {
            Binop::And => query_matches(&left, tagset) && query_matches(&right, tagset),
            Binop::Or => query_matches(&left, tagset) || query_matches(&right, tagset),
        },
        Query::Unop { op, query, .. } => match op {
            Unop::Not => !query_matches(&query, tagset),
        },
    }
}

pub fn get_id_query(q: &Query) -> Option<String> {
    match q {
        Query::Glob { tag, pattern, .. }
            if tag == "id" && pattern.as_str().chars().all(char::is_alphanumeric) =>
        {
            Some(pattern.as_str().to_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_value() {
        assert_eq!(
            parse("foo").unwrap(),
            Query::ExistsAssertion {
                tag: "foo".to_owned(),
                span: (0, 3),
            }
        );

        assert_eq!(
            parse(" \t foo").unwrap(),
            Query::ExistsAssertion {
                tag: "foo".to_owned(),
                span: (3, 6),
            }
        );

        assert_eq!(
            parse("\"foo\"").unwrap(),
            Query::ExistsAssertion {
                tag: "foo".to_owned(),
                span: (0, 5),
            }
        );

        assert_eq!(
            parse("\"f\\\"oo\"").unwrap(),
            Query::ExistsAssertion {
                tag: "f\"oo".to_owned(),
                span: (0, 7),
            }
        );
    }

    #[test]
    fn test_is_id_query() {
        assert_eq!(
            get_id_query(&parse("id=123").unwrap()),
            Some("123".to_owned())
        );
        assert_eq!(get_id_query(&parse("foo=123").unwrap()), None);
    }

    #[test]
    fn test_parse_paren() {
        assert_eq!(
            parse("(foo)").unwrap(),
            Query::ExistsAssertion {
                tag: "foo".to_owned(),
                span: (1, 4),
            }
        );

        assert_eq!(
            parse(" ( foo; ) ").unwrap(),
            Query::ExistsAssertion {
                tag: "foo".to_owned(),
                span: (3, 6),
            }
        );
    }

    #[test]
    fn test_parse_not() {
        let q = parse("~foo").unwrap();

        match q {
            Query::Unop {
                op: Unop::Not,
                span: (0, 5),
                ..
            } => (),
            _ => panic!(format!("{:?}", q)),
        }
    }

    #[test]
    fn test_parse_glob() {
        match parse("foo==123").unwrap() {
            Query::Glob { span: (0, 8), .. } => (),
            v => panic!(format!("{:?}", v)),
        };
        match parse("foo=123").unwrap() {
            Query::Glob { span: (0, 7), .. } => (),
            v => panic!(format!("{:?}", v)),
        };
    }

    #[test]
    fn test_parse_binop() {
        assert_eq!(
            parse("foo; and bar").unwrap(),
            Query::Binop {
                op: Binop::And,
                left: Box::new(Query::ExistsAssertion {
                    tag: "foo".to_owned(),
                    span: (0, 3),
                }),
                right: Box::new(Query::ExistsAssertion {
                    tag: "bar".to_owned(),
                    span: (9, 12),
                }),
                span: (0, 13),
            }
        );

        assert_eq!(
            parse("foo; and bar; and baz;").unwrap(),
            Query::Binop {
                op: Binop::And,

                left: Box::new(Query::Binop {
                    op: Binop::And,
                    left: Box::new(Query::ExistsAssertion {
                        tag: "foo".to_owned(),
                        span: (0, 3),
                    }),
                    right: Box::new(Query::ExistsAssertion {
                        tag: "bar".to_owned(),
                        span: (9, 12),
                    }),
                    span: (0, 14),
                }),

                right: Box::new(Query::ExistsAssertion {
                    tag: "baz".to_owned(),
                    span: (18, 21),
                }),

                span: (0, 23),
            }
        );

        assert_eq!(
            parse("foo; and (bar; or baz)").unwrap(),
            Query::Binop {
                op: Binop::And,

                left: Box::new(Query::ExistsAssertion {
                    tag: "foo".to_owned(),
                    span: (0, 3),
                }),

                right: Box::new(Query::Binop {
                    op: Binop::Or,
                    left: Box::new(Query::ExistsAssertion {
                        tag: "bar".to_owned(),
                        span: (10, 13),
                    }),
                    right: Box::new(Query::ExistsAssertion {
                        tag: "baz".to_owned(),
                        span: (18, 21),
                    }),
                    span: (10, 21),
                }),

                span: (0, 23),
            }
        );
    }

    #[test]
    fn test_query_match() {
        let mut tagset = BTreeMap::<String, Option<String>>::new();
        tagset.insert("foo".to_string(), Some("123".to_string()));
        tagset.insert("bar".to_string(), None);

        assert!(query_matches(&parse("foo;").unwrap(), &tagset));
        assert!(query_matches(&parse("foo; and bar").unwrap(), &tagset));
        assert!(query_matches(&parse("bar; or foo").unwrap(), &tagset));
        assert!(query_matches(&parse("foo=12*").unwrap(), &tagset));
        assert!(query_matches(&parse("foo=12?").unwrap(), &tagset));
        assert!(query_matches(&parse("foo=*; and bar").unwrap(), &tagset));
        assert!(query_matches(&parse("~foo=xxx").unwrap(), &tagset));
        assert!(query_matches(&parse("foo==123; and bar").unwrap(), &tagset));
        assert!(!query_matches(&parse("~foo==123").unwrap(), &tagset));
        assert!(!query_matches(&parse("foo==*;").unwrap(), &tagset));
    }
}
