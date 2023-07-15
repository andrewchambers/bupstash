use super::xglobset;
use super::xid::*;
use std::collections::BTreeMap;

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum ParseError {
    #[error("syntax error, {msg}")]
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
pub enum AgeAssertion {
    OlderThan,
    NewerThan,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Query {
    Glob {
        tag: String,
        pattern: xglobset::GlobMatcher,
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
    AgeAssertion {
        op: AgeAssertion,
        span: (usize, usize),
        duration: std::time::Duration,
    },
}

fn is_tag_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

macro_rules! impl_binop {
    ($name:ident, $opi:ident, $ops:literal , $sub:ident) => {
        fn $name(&mut self) -> Result<Query, ParseError> {
            let op = $ops;
            let mut l: Query;
            let (_, start_pos) = self.peek();
            l = self.$sub()?;
            loop {
                if !self.lookahead_sep(op) {
                    return Ok(l);
                }
                self.advance(op.chars().count() + 1);

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
            None => ('•', self.offset),
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
            None => ('•', offset),
        }
    }

    fn is_eof(&self) -> bool {
        self.offset == self.query_chars.len()
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

    fn lookahead_sep(&mut self, op: &str) -> bool {
        if !self.lookahead(op) {
            return false;
        }
        match self.query_chars.get(self.offset + op.chars().count()) {
            Some('•') => true,
            None => true,
            Some(_) => false,
        }
    }

    fn consume_if_matches(&mut self, s: &str) -> bool {
        if self.lookahead(s) {
            self.advance(s.chars().count());
            true
        } else {
            false
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
            self.advance(expected.chars().count());
            Ok(())
        }
    }

    fn parse(&mut self) -> Result<Query, ParseError> {
        let v = self.parse_expr()?;

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
        let (c, _) = self.peek();
        if c == '[' {
            self.expect("[")?;
            self.consume_if_matches("•");
            let v = self.parse_expr()?;
            self.expect("]")?;
            self.consume_if_matches("•");
            Ok(v)
        } else if c == '~' {
            self.parse_unop()
        } else if self.lookahead("older-than•") || self.lookahead("newer-than•") {
            self.parse_age_assertion()
        } else {
            self.parse_eq()
        }
    }

    fn parse_age_assertion(&mut self) -> Result<Query, ParseError> {
        let (_, start_pos) = self.peek();

        let op = if self.consume_if_matches("older-than•") {
            AgeAssertion::OlderThan
        } else if self.consume_if_matches("newer-than•") {
            AgeAssertion::NewerThan
        } else {
            unreachable!()
        };

        let (_, duration_start_pos) = self.peek();

        let mut d = String::new();
        loop {
            match self.peek() {
                (c, _) if c != '•' => {
                    self.advance(1);
                    d.push(c);
                }
                _ => break,
            }
        }
        let (_, end_pos) = self.peek();
        self.consume_if_matches("•");

        match humantime::parse_duration(&d) {
            Ok(duration) => Ok(Query::AgeAssertion {
                op,
                duration,
                span: (start_pos, end_pos),
            }),
            Err(err) => Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: format!("error parsing duration: {}", err),
                span: (duration_start_pos, end_pos),
            }),
        }
    }

    fn parse_tag(&mut self) -> Result<String, ParseError> {
        let (c, pos) = self.peek();

        if !is_tag_char(c) {
            return Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: "expected a tag character".to_string(),
                span: (pos, pos),
            });
        }
        self.get();

        let mut v = String::new();
        v.push(c);
        loop {
            match self.peek() {
                (c, _) if is_tag_char(c) => {
                    self.advance(1);
                    v.push(c);
                }
                _ => break,
            }
        }

        Ok(v)
    }

    fn parse_value(&mut self) -> String {
        let (c, _) = self.peek();

        if c == '•' {
            self.advance(1);
            return "".to_string();
        }

        self.get();

        let mut v = String::new();
        v.push(c);
        loop {
            match self.peek() {
                (c, _) if c != '•' => {
                    self.advance(1);
                    v.push(c);
                }
                _ => break,
            }
        }
        self.consume_if_matches("•");
        v
    }

    fn parse_eq(&mut self) -> Result<Query, ParseError> {
        let (_, tag_pos) = self.peek();
        let tag = self.parse_tag()?;
        let (_, tag_end_pos) = self.peek();

        let escape: bool;

        if self.consume_if_matches("==") {
            escape = true;
        } else if self.consume_if_matches("=") {
            escape = false;
        } else {
            return Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: "expected '=' after tag".to_string(),
                span: (tag_pos, tag_end_pos),
            });
        }

        let raw_pattern = self.parse_value();
        let (_, end_pos) = self.peek();

        let pattern = if escape {
            //Ok(globset::Glob::new_escaped(&raw_pattern))
            Ok(globset::Glob::new(&xglobset::escape(&raw_pattern)).unwrap())
        } else {
            globset::Glob::new(&raw_pattern)
        };

        let pattern = match pattern {
            Ok(pattern) => pattern.compile_matcher(),
            Err(err) => {
                return Err(ParseError::SyntaxError {
                    query: self.query_chars.iter().collect(),
                    msg: format!("invalid glob pattern: {}", err),
                    span: (tag_pos, end_pos),
                })
            }
        };

        self.consume_if_matches("•");

        Ok(Query::Glob {
            tag,
            pattern: pattern.into(),
            span: (tag_pos, end_pos),
        })
    }

    fn parse_unop(&mut self) -> Result<Query, ParseError> {
        let (op, op_pos) = self.peek();

        let op = if self.consume_if_matches("~") {
            self.consume_if_matches("•");
            Unop::Not
        } else {
            return Err(ParseError::SyntaxError {
                query: self.query_chars.iter().collect(),
                msg: format!("unknown unary operator: {}", op),
                span: (op_pos, op_pos),
            });
        };

        let query = Box::new(self.parse_base()?);
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
            let err_span = query_span.subspan(
                indices.get(span.0).unwrap_or(&indices[indices.len() - 1]).0 as u64,
                indices.get(span.1).unwrap_or(&indices[indices.len() - 1]).0 as u64,
            );
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

pub struct QueryContext<'a> {
    pub age: std::time::Duration,
    pub tagset: &'a BTreeMap<String, String>,
}

pub fn query_matches(q: &Query, ctx: &QueryContext) -> bool {
    match q {
        Query::Glob { tag, pattern, .. } => match ctx.tagset.get(tag) {
            Some(v) => pattern.is_match(v),
            None => false,
        },
        Query::Binop {
            op, left, right, ..
        } => match op {
            Binop::And => query_matches(left, ctx) && query_matches(right, ctx),
            Binop::Or => query_matches(left, ctx) || query_matches(right, ctx),
        },
        Query::Unop { op, query, .. } => match op {
            Unop::Not => !query_matches(query, ctx),
        },
        Query::AgeAssertion { op, duration, .. } => match op {
            AgeAssertion::OlderThan => ctx.age > *duration,
            AgeAssertion::NewerThan => ctx.age < *duration,
        },
    }
}

pub struct QueryEncryptedContext<'a> {
    pub tagset: &'a BTreeMap<String, String>,
}

pub fn query_matches_encrypted(q: &Query, ctx: &QueryEncryptedContext) -> bool {
    match q {
        Query::Glob { tag, pattern, .. } => match ctx.tagset.get(tag) {
            Some(v) => pattern.is_match(v),
            None => false,
        },
        Query::Binop {
            op, left, right, ..
        } => match op {
            Binop::And => query_matches_encrypted(left, ctx) && query_matches_encrypted(right, ctx),
            Binop::Or => query_matches_encrypted(left, ctx) || query_matches_encrypted(right, ctx),
        },
        Query::Unop { op, query, .. } => match op {
            Unop::Not => !query_matches_encrypted(query, ctx),
        },
        Query::AgeAssertion { .. } => false,
    }
}

pub fn get_id_query(q: &Query) -> Option<Xid> {
    match q {
        Query::Glob { tag, pattern, .. }
            if tag == "id" && pattern.glob().glob().chars().all(char::is_alphanumeric) =>
        {
            if let Ok(xid) = Xid::parse(pattern.glob().glob()) {
                Some(xid)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_id_query() {
        assert_eq!(
            get_id_query(&parse("id=11223344556677881122334455667788").unwrap()),
            Some(Xid::parse(&"11223344556677881122334455667788").unwrap())
        );
        assert_eq!(get_id_query(&parse("foo=123").unwrap()), None);
    }

    #[test]
    fn test_query_match() {
        let mut tagset = BTreeMap::<String, String>::new();
        tagset.insert("foo".to_string(), "123".to_string());
        tagset.insert("bar".to_string(), "".to_string());
        let ctx = QueryContext {
            age: std::time::Duration::new(5, 0),
            tagset: &tagset,
        };
        let ectx = QueryEncryptedContext { tagset: &tagset };
        assert!(query_matches(&parse("foo=123•and•bar=").unwrap(), &ctx));
        assert!(query_matches(&parse("foo=12*").unwrap(), &ctx));
        assert!(query_matches(&parse("foo=12?").unwrap(), &ctx));
        assert!(query_matches(&parse("~foo=xxx").unwrap(), &ctx));
        assert!(query_matches(&parse("older-than•2s").unwrap(), &ctx));
        assert!(query_matches(&parse("newer-than•6s").unwrap(), &ctx));
        assert!(!query_matches(&parse("older-than•6s").unwrap(), &ctx));
        assert!(!query_matches(&parse("newer-than•2s").unwrap(), &ctx));
        assert!(!query_matches(&parse("~•[•foo==123•]").unwrap(), &ctx));

        assert!(query_matches_encrypted(
            &parse("foo=123•and•bar=").unwrap(),
            &ectx
        ));
        assert!(query_matches_encrypted(&parse("foo=12*").unwrap(), &ectx));
        assert!(query_matches_encrypted(&parse("foo=12?").unwrap(), &ectx));
        assert!(query_matches_encrypted(&parse("~foo=xxx").unwrap(), &ectx));
        assert!(!query_matches_encrypted(
            &parse("older-than•2s").unwrap(),
            &ectx
        ));
        assert!(!query_matches_encrypted(
            &parse("newer-than•6s").unwrap(),
            &ectx
        ));
    }
}
