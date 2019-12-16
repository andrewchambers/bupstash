use failure::Fail;

#[derive(Eq, PartialEq, Debug, Fail)]
pub enum ParseError {
    #[fail(display = "syntax error, {} at character {}", msg, pos)]
    SyntaxError { msg: String, pos: usize },
}

#[derive(Eq, PartialEq, Debug)]
pub enum Binop {
    And,
    Or,
}

#[derive(Eq, PartialEq, Debug)]
pub enum AssertionOp {
    Equals,
    NotEquals,
    Glob,
    NotGlob,
}

#[derive(Eq, PartialEq, Debug)]
pub enum QueryAST {
    TagValueAssertion {
        op: AssertionOp,
        tag: String,
        value: String,
        span: (usize, usize),
    },
    TagExistsAssertion {
        tag: String,
        span: (usize, usize),
    },
    Binop {
        op: Binop,
        span: (usize, usize),
        left: Box<QueryAST>,
        right: Box<QueryAST>,
    },
}

fn is_value_char(c: char) -> bool {
    match c {
        // FIXME, we can probably allow a lot more.
        'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '*' | '@' => true,
        _ => false,
    }
}

fn is_ws(c: char) -> bool {
    match c {
        ' ' | '\t' | '\n' => true,
        _ => false,
    }
}

macro_rules! impl_binop {
    ($name:ident, $opi:ident, $ops:literal , $sub:ident) => {
    fn $name(&mut self) -> Result<QueryAST, ParseError> {
        let op = $ops;
        let mut l: QueryAST;
        self.skip_ws();
        let (_, start_pos) = self.peek();
        l = self.$sub()?;
        loop {
          self.skip_ws();
          if !self.look_ahead_with_ws(op) {
            return Ok(l);
          }
          self.advance(op.len());
          self.skip_ws();
          let r = self.$sub()?;
          let (_, end_pos) = self.peek();
          l = QueryAST::Binop{
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
    s: Vec<char>,
    offset: usize,
}

impl Parser {
    fn peek(&mut self) -> (char, usize) {
        match self.s.get(self.offset) {
            Some(c) => (*c, self.offset),
            None => ('\0', self.offset),
        }
    }

    fn advance(&mut self, count: usize) {
        self.offset += count;
    }

    fn get(&mut self) -> (char, usize) {
        match self.s.get(self.offset) {
            Some(c) => {
                let offset = self.offset;
                self.offset += 1;
                (*c, offset)
            }
            None => ('\0', self.offset),
        }
    }

    fn skip_ws(&mut self) {
        loop {
            let (c, _) = self.peek();
            if !is_ws(c) {
                return;
            }
            self.advance(1);
        }
    }

    fn lookahead(&mut self, lookahead: &str) -> bool {
        for (i, c) in lookahead.chars().enumerate() {
            match self.s.get(self.offset + i) {
                Some(gotc) if c == *gotc => (),
                _ => return false,
            }
        }
        true
    }

    fn consume_if_matches(&mut self, s: &str) -> bool {
        if self.lookahead(s) {
            self.advance(s.len());
            true
        } else {
            false
        }
    }

    fn look_ahead_with_ws(&mut self, op: &str) -> bool {
        if !self.lookahead(op) {
            return false;
        }
        match self.s.get(self.offset + op.len()) {
            Some(c) => return is_ws(*c),
            _ => false,
        }
    }

    fn expect(&mut self, expected: &str) -> Result<(), ParseError> {
        if !self.lookahead(expected) {
            Err(ParseError::SyntaxError {
                msg: format!("expected '{}'", expected),
                pos: self.offset,
            })
        } else {
            self.advance(expected.len());
            Ok(())
        }
    }

    fn parse(&mut self) -> Result<QueryAST, ParseError> {
        self.parse_expr()
    }

    fn parse_expr(&mut self) -> Result<QueryAST, ParseError> {
        self.parse_and()
    }

    impl_binop!(parse_and, And, "and", parse_or);
    impl_binop!(parse_or, Or, "or", parse_base);

    fn parse_base(&mut self) -> Result<QueryAST, ParseError> {
        self.skip_ws();
        let (c, _offset) = self.peek();
        if c == '(' {
            self.expect("(")?;
            let v = self.parse_expr()?;
            self.expect(")")?;
            Ok(v)
        } else {
            self.parse_tag_assert()
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
                        msg: format!("unexpected end of input"),
                        pos,
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
        self.skip_ws();
        let (c, pos) = self.peek();

        if c == '"' {
            return self.parse_quoted_value();
        }

        if !is_value_char(c) {
            return Err(ParseError::SyntaxError {
                msg: format!("expected a value literal start character"),
                pos,
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
                    ()
                }
                _ => break,
            }
        }

        Ok(v)
    }

    fn parse_tag_assert(&mut self) -> Result<QueryAST, ParseError> {
        self.skip_ws();
        let (_, tag_pos) = self.peek();
        let tag = self.parse_value()?;
        let (_, tag_end_pos) = self.peek();
        self.skip_ws();

        let op: AssertionOp;

        if self.consume_if_matches("!==") {
            op = AssertionOp::NotEquals;
        } else if self.consume_if_matches("!=") {
            op = AssertionOp::NotGlob
        } else if self.consume_if_matches("==") {
            op = AssertionOp::Equals;
        } else if self.consume_if_matches("=") {
            op = AssertionOp::Glob;
        } else {
            return Ok(QueryAST::TagExistsAssertion {
                tag,
                span: (tag_pos, tag_end_pos),
            });
        }

        let value = self.parse_value()?;
        let (_, end_pos) = self.peek();

        return Ok(QueryAST::TagValueAssertion {
            op,
            tag,
            value,
            span: (tag_pos, end_pos),
        });
    }
}

pub fn parse(s: &str) -> Result<QueryAST, ParseError> {
    let mut p = Parser {
        s: s.chars().collect(),
        offset: 0,
    };

    p.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_value() {
        assert_eq!(
            parse("foo").unwrap(),
            QueryAST::TagExistsAssertion {
                tag: "foo".to_owned(),
                span: (0, 3),
            }
        );

        assert_eq!(
            parse(" \t foo").unwrap(),
            QueryAST::TagExistsAssertion {
                tag: "foo".to_owned(),
                span: (3, 6),
            }
        );

        assert_eq!(
            parse("\"foo\"").unwrap(),
            QueryAST::TagExistsAssertion {
                tag: "foo".to_owned(),
                span: (0, 5),
            }
        );

        assert_eq!(
            parse("\"f\\\"oo\"").unwrap(),
            QueryAST::TagExistsAssertion {
                tag: "f\"oo".to_owned(),
                span: (0, 7),
            }
        );
    }

    #[test]
    fn test_parse_paren() {
        assert_eq!(
            parse("(foo)").unwrap(),
            QueryAST::TagExistsAssertion {
                tag: "foo".to_owned(),
                span: (1, 4),
            }
        );

        assert_eq!(
            parse(" ( foo ) ").unwrap(),
            QueryAST::TagExistsAssertion {
                tag: "foo".to_owned(),
                span: (3, 6),
            }
        );
    }

    #[test]
    fn test_value_assert() {
        assert_eq!(
            parse("foo=123").unwrap(),
            QueryAST::TagValueAssertion {
                op: AssertionOp::Glob,
                tag: "foo".to_owned(),
                value: "123".to_owned(),
                span: (0, 7),
            }
        );

        assert_eq!(
            parse("foo==123").unwrap(),
            QueryAST::TagValueAssertion {
                op: AssertionOp::Equals,
                tag: "foo".to_owned(),
                value: "123".to_owned(),
                span: (0, 8),
            }
        );
    }

    #[test]
    fn test_parse_binop() {
        assert_eq!(
            parse("foo and bar").unwrap(),
            QueryAST::Binop {
                op: Binop::And,
                left: Box::new(QueryAST::TagExistsAssertion {
                    tag: "foo".to_owned(),
                    span: (0, 3),
                }),
                right: Box::new(QueryAST::TagExistsAssertion {
                    tag: "bar".to_owned(),
                    span: (8, 11),
                }),
                span: (0, 11),
            }
        );

        assert_eq!(
            parse("foo and bar and baz").unwrap(),
            QueryAST::Binop {
                op: Binop::And,

                left: Box::new(QueryAST::Binop {
                    op: Binop::And,
                    left: Box::new(QueryAST::TagExistsAssertion {
                        tag: "foo".to_owned(),
                        span: (0, 3),
                    }),
                    right: Box::new(QueryAST::TagExistsAssertion {
                        tag: "bar".to_owned(),
                        span: (8, 11),
                    }),
                    span: (0, 12),
                }),

                right: Box::new(QueryAST::TagExistsAssertion {
                    tag: "baz".to_owned(),
                    span: (16, 19),
                }),

                span: (0, 19),
            }
        );

        assert_eq!(
            parse("foo and (bar or baz)").unwrap(),
            QueryAST::Binop {
                op: Binop::And,

                left: Box::new(QueryAST::TagExistsAssertion {
                    tag: "foo".to_owned(),
                    span: (0, 3),
                }),

                right: Box::new(QueryAST::Binop {
                    op: Binop::Or,
                    left: Box::new(QueryAST::TagExistsAssertion {
                        tag: "bar".to_owned(),
                        span: (9, 12),
                    }),
                    right: Box::new(QueryAST::TagExistsAssertion {
                        tag: "baz".to_owned(),
                        span: (16, 19),
                    }),
                    span: (9, 19),
                }),

                span: (0, 20),
            }
        );
    }
}
