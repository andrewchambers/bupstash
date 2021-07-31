// Copyright 2016-2017 Jonathan Creekmore
// Copyright 2020 Andrew Chambers
//
// Licensed under the MIT license <LICENSE.md or
// http://opensource.org/licenses/MIT>. This file may not be
// copied, modified, or distributed except according to those terms.

use super::base64;
use once_cell::sync::Lazy;
use regex::bytes::{Captures, Regex};
use std::error::Error;
use std::fmt;
use std::str;

/// The `pem` error type.
#[derive(Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum PemError {
    MismatchedTags(String, String),
    MalformedFraming,
    MissingBeginTag,
    MissingEndTag,
    MissingData,
    InvalidData,
    NotUtf8(::std::str::Utf8Error),
}

impl fmt::Display for PemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PemError::MismatchedTags(b, e) => {
                write!(f, "mismatching BEGIN (\"{}\") and END (\"{}\") tags", b, e)
            }
            PemError::MalformedFraming => write!(f, "malformedframing"),
            PemError::MissingBeginTag => write!(f, "missing BEGIN tag"),
            PemError::MissingEndTag => write!(f, "missing END tag"),
            PemError::MissingData => write!(f, "missing data"),
            PemError::InvalidData => write!(f, "invalid data"),
            PemError::NotUtf8(e) => write!(f, "invalid utf-8 value: {}", e),
        }
    }
}

impl Error for PemError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            // Errors originating from other libraries.
            PemError::NotUtf8(e) => Some(e),
            // Errors directly originating from `pem-rs`.
            _ => None,
        }
    }
}

/// The `pem` result type.
pub type Result<T> = ::std::result::Result<T, PemError>;

const REGEX_STR: &str = r"(?s)-----BEGIN (?P<begin>.*?)-----[ \t\n\r]*(?P<data>.*?)-----END (?P<end>.*?)-----[ \t\n\r]*";

/// The line length for PEM encoding
const LINE_WRAP: usize = 64;

static ASCII_ARMOR: Lazy<Regex> = Lazy::new(|| Regex::new(REGEX_STR).unwrap());

/// Enum describing line endings
#[derive(Debug, Clone, Copy)]
pub enum LineEnding {
    /// Windows-like (`\r\n`)
    Crlf,
    /// Unix-like (`\n`)
    Lf,
}

/// Configuration for Pem encoding
#[derive(Debug, Clone, Copy)]
pub struct EncodeConfig {
    /// Line ending to use during encoding
    pub line_ending: LineEnding,
}

/// A representation of Pem-encoded data
#[derive(PartialEq, Debug)]
pub struct Pem {
    /// The tag extracted from the Pem-encoded data
    pub tag: String,
    /// The binary contents of the Pem-encoded data
    pub contents: Vec<u8>,
}

impl Pem {
    fn new_from_captures(caps: Captures) -> Result<Pem> {
        fn as_utf8(bytes: &[u8]) -> Result<&str> {
            str::from_utf8(bytes).map_err(PemError::NotUtf8)
        }

        // Verify that the begin section exists
        let tag = as_utf8(
            caps.name("begin")
                .ok_or(PemError::MissingBeginTag)?
                .as_bytes(),
        )?;
        if tag.is_empty() {
            return Err(PemError::MissingBeginTag);
        }

        // as well as the end section
        let tag_end = as_utf8(caps.name("end").ok_or(PemError::MissingEndTag)?.as_bytes())?;
        if tag_end.is_empty() {
            return Err(PemError::MissingEndTag);
        }

        // The beginning and the end sections must match
        if tag != tag_end {
            return Err(PemError::MismatchedTags(tag.into(), tag_end.into()));
        }

        // If they did, then we can grab the data section
        let raw_data = as_utf8(caps.name("data").ok_or(PemError::MissingData)?.as_bytes())?;

        // We need to get rid of newlines for base64::decode
        // As base64 requires an AsRef<[u8]>, this must involve a copy
        let data: String = raw_data.lines().map(str::trim_end).collect();

        // And decode it from Base64 into a vector of u8
        let contents = match base64::decode(&data) {
            Some(contents) => contents,
            None => return Err(PemError::InvalidData),
        };

        Ok(Pem {
            tag: tag.to_owned(),
            contents,
        })
    }
}

/// Parses a single PEM-encoded data from a data-type that can be dereferenced as a [u8].
///
/// # Example: parse PEM-encoded data from a Vec<u8>
/// ```rust
///
/// use pem::parse;
///
/// const SAMPLE: &'static str = "-----BEGIN RSA PRIVATE KEY-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END RSA PRIVATE KEY-----
/// ";
/// let SAMPLE_BYTES: Vec<u8> = SAMPLE.into();
///
///  let pem = parse(SAMPLE_BYTES).unwrap();
///  assert_eq!(pem.tag, "RSA PRIVATE KEY");
/// ```
///
/// # Example: parse PEM-encoded data from a String
/// ```rust
///
/// use pem::parse;
///
/// const SAMPLE: &'static str = "-----BEGIN RSA PRIVATE KEY-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END RSA PRIVATE KEY-----
/// ";
/// let SAMPLE_STRING: String = SAMPLE.into();
///
///  let pem = parse(SAMPLE_STRING).unwrap();
///  assert_eq!(pem.tag, "RSA PRIVATE KEY");
/// ```
pub fn parse<B: AsRef<[u8]>>(input: B) -> Result<Pem> {
    ASCII_ARMOR
        .captures(input.as_ref())
        .ok_or(PemError::MalformedFraming)
        .and_then(Pem::new_from_captures)
}

/// Parses a set of PEM-encoded data from a data-type that can be dereferenced as a [u8].
///
/// # Example: parse a set of PEM-encoded data from a Vec<u8>
///
/// ```rust
///
/// use pem::parse_many;
///
/// const SAMPLE: &'static str = "-----BEGIN INTERMEDIATE CERT-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END INTERMEDIATE CERT-----
///
/// -----BEGIN CERTIFICATE-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END CERTIFICATE-----
/// ";
/// let SAMPLE_BYTES: Vec<u8> = SAMPLE.into();
///
///  let pems = parse_many(SAMPLE_BYTES);
///  assert_eq!(pems.len(), 2);
///  assert_eq!(pems[0].tag, "INTERMEDIATE CERT");
///  assert_eq!(pems[1].tag, "CERTIFICATE");
/// ```
///
/// # Example: parse a set of PEM-encoded data from a String
///
/// ```rust
///
/// use pem::parse_many;
///
/// const SAMPLE: &'static str = "-----BEGIN INTERMEDIATE CERT-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END INTERMEDIATE CERT-----
///
/// -----BEGIN CERTIFICATE-----
/// MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
/// dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
/// 2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
/// AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
/// DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
/// TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
/// ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
/// -----END CERTIFICATE-----
/// ";
///  let SAMPLE_STRING: Vec<u8> = SAMPLE.into();
///
///  let pems = parse_many(SAMPLE_STRING);
///  assert_eq!(pems.len(), 2);
///  assert_eq!(pems[0].tag, "INTERMEDIATE CERT");
///  assert_eq!(pems[1].tag, "CERTIFICATE");
/// ```
pub fn parse_many<B: AsRef<[u8]>>(input: B) -> Vec<Pem> {
    // Each time our regex matches a PEM section, we need to decode it.
    ASCII_ARMOR
        .captures_iter(input.as_ref())
        .filter_map(|caps| Pem::new_from_captures(caps).ok())
        .collect()
}

/// Encode a PEM struct into a PEM-encoded data string
///
/// # Example
/// ```rust
///  use pem::{Pem, encode};
///
///  let pem = Pem {
///     tag: String::from("FOO"),
///     contents: vec![1, 2, 3, 4],
///   };
///   encode(&pem);
/// ```
pub fn encode(pem: &Pem) -> String {
    encode_config(
        pem,
        EncodeConfig {
            line_ending: LineEnding::Crlf,
        },
    )
}

/// Encode a PEM struct into a PEM-encoded data string with additional
/// configuration options
///
/// # Example
/// ```rust
///  use pem::{Pem, encode_config, EncodeConfig, LineEnding};
///
///  let pem = Pem {
///     tag: String::from("FOO"),
///     contents: vec![1, 2, 3, 4],
///   };
///   encode_config(&pem, EncodeConfig { line_ending: LineEnding::Lf });
/// ```
pub fn encode_config(pem: &Pem, config: EncodeConfig) -> String {
    let line_ending = match config.line_ending {
        LineEnding::Crlf => "\r\n",
        LineEnding::Lf => "\n",
    };

    let mut output = String::new();

    let contents = if pem.contents.is_empty() {
        String::from("")
    } else {
        base64::encode(&pem.contents)
    };

    output.push_str(&format!("-----BEGIN {}-----{}", pem.tag, line_ending));
    for c in contents.as_bytes().chunks(LINE_WRAP) {
        output.push_str(&format!("{}{}", str::from_utf8(c).unwrap(), line_ending));
    }
    output.push_str(&format!("-----END {}-----{}", pem.tag, line_ending));

    output
}

/// Encode multiple PEM structs into a PEM-encoded data string
///
/// # Example
/// ```rust
///  use pem::{Pem, encode_many};
///
///  let data = vec![
///     Pem {
///         tag: String::from("FOO"),
///         contents: vec![1, 2, 3, 4],
///     },
///     Pem {
///         tag: String::from("BAR"),
///         contents: vec![5, 6, 7, 8],
///     },
///   ];
///   encode_many(&data);
/// ```
pub fn encode_many(pems: &[Pem]) -> String {
    pems.iter()
        .map(encode)
        .collect::<Vec<String>>()
        .join("\r\n")
}

/// Encode multiple PEM structs into a PEM-encoded data string with additional
/// configuration options
///
/// Same config will be used for each PEM struct.
///
/// # Example
/// ```rust
///  use pem::{Pem, encode_many_config, EncodeConfig, LineEnding};
///
///  let data = vec![
///     Pem {
///         tag: String::from("FOO"),
///         contents: vec![1, 2, 3, 4],
///     },
///     Pem {
///         tag: String::from("BAR"),
///         contents: vec![5, 6, 7, 8],
///     },
///   ];
///   encode_many_config(&data, EncodeConfig { line_ending: LineEnding::Lf });
/// ```
pub fn encode_many_config(pems: &[Pem], config: EncodeConfig) -> String {
    let line_ending = match config.line_ending {
        LineEnding::Crlf => "\r\n",
        LineEnding::Lf => "\n",
    };
    pems.iter()
        .map(|value| encode_config(value, config))
        .collect::<Vec<String>>()
        .join(line_ending)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CRLF: &'static str = "-----BEGIN RSA PRIVATE KEY-----\r
MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc\r
dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO\r
2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei\r
AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un\r
DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT\r
TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh\r
ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ\r
-----END RSA PRIVATE KEY-----\r
\r
-----BEGIN RSA PUBLIC KEY-----\r
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo\r
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0\r
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI\r
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk\r
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6\r
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g\r
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg\r
-----END RSA PUBLIC KEY-----\r
";

    const SAMPLE_LF: &'static str = "-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBAOsfi5AGYhdRs/x6q5H7kScxA0Kzzqe6WI6gf6+tc6IvKQJo5rQc
dWWSQ0nRGt2hOPDO+35NKhQEjBQxPh/v7n0CAwEAAQJBAOGaBAyuw0ICyENy5NsO
2gkT00AWTSzM9Zns0HedY31yEabkuFvrMCHjscEF7u3Y6PB7An3IzooBHchsFDei
AAECIQD/JahddzR5K3A6rzTidmAf1PBtqi7296EnWv8WvpfAAQIhAOvowIXZI4Un
DXjgZ9ekuUjZN+GUQRAVlkEEohGLVy59AiEA90VtqDdQuWWpvJX0cM08V10tLXrT
TTGsEtITid1ogAECIQDAaFl90ZgS5cMrL3wCeatVKzVUmuJmB/VAmlLFFGzK0QIh
ANJGc7AFk4fyFD/OezhwGHbWmo/S+bfeAiIh2Ss2FxKJ
-----END RSA PRIVATE KEY-----

-----BEGIN RSA PUBLIC KEY-----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END RSA PUBLIC KEY-----
";

    #[test]
    fn test_parse_works() {
        let pem = parse(SAMPLE_CRLF).unwrap();
        assert_eq!(pem.tag, "RSA PRIVATE KEY");
    }

    #[test]
    fn test_parse_invalid_framing() {
        let input = "--BEGIN data-----
        -----END data-----";
        assert_eq!(parse(&input), Err(PemError::MalformedFraming));
    }

    #[test]
    fn test_parse_invalid_begin() {
        let input = "-----BEGIN -----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END RSA PUBLIC KEY-----";
        assert_eq!(parse(&input), Err(PemError::MissingBeginTag));
    }

    #[test]
    fn test_parse_invalid_end() {
        let input = "-----BEGIN DATA-----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oYo
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END -----";
        assert_eq!(parse(&input), Err(PemError::MissingEndTag));
    }

    #[test]
    fn test_parse_invalid_data() {
        let input = "-----BEGIN DATA-----
MIIBOgIBAAJBAMIeCnn9G/7g2Z6J+qHOE2XCLLuPoh5NHTO2Fm+PbzBvafBo0oY?
QVVy7frzxmOqx6iIZBxTyfAQqBPO3Br59BMCAwEAAQJAX+PjHPuxdqiwF6blTkS0
RFI1MrnzRbCmOkM6tgVO0cd6r5Z4bDGLusH9yjI9iI84gPRjK0AzymXFmBGuREHI
sQIhAPKf4pp+Prvutgq2ayygleZChBr1DC4XnnufBNtaswyvAiEAzNGVKgNvzuhk
ijoUXIDruJQEGFGvZTsi1D2RehXiT90CIQC4HOQUYKCydB7oWi1SHDokFW2yFyo6
/+lf3fgNjPI6OQIgUPmTFXciXxT1msh3gFLf3qt2Kv8wbr9Ad9SXjULVpGkCIB+g
RzHX0lkJl9Stshd/7Gbt65/QYq+v+xvAeT0CoyIg
-----END DATA-----";
        match parse(&input) {
            Err(PemError::InvalidData) => (),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_parse_empty_data() {
        let input = "-----BEGIN DATA-----
-----END DATA-----";
        let pem = parse(&input).unwrap();
        assert_eq!(pem.contents.len(), 0);
    }

    #[test]
    fn test_parse_many_works() {
        let pems = parse_many(SAMPLE_CRLF);
        assert_eq!(pems.len(), 2);
        assert_eq!(pems[0].tag, "RSA PRIVATE KEY");
        assert_eq!(pems[1].tag, "RSA PUBLIC KEY");
    }

    #[test]
    fn test_encode_empty_contents() {
        let pem = Pem {
            tag: String::from("FOO"),
            contents: vec![],
        };
        let encoded = encode(&pem);
        assert!(encoded != "");

        let pem_out = parse(&encoded).unwrap();
        assert_eq!(&pem, &pem_out);
    }

    #[test]
    fn test_encode_contents() {
        let pem = Pem {
            tag: String::from("FOO"),
            contents: vec![1, 2, 3, 4],
        };
        let encoded = encode(&pem);
        assert!(encoded != "");

        let pem_out = parse(&encoded).unwrap();
        assert_eq!(&pem, &pem_out);
    }

    #[test]
    fn test_encode_many() {
        let pems = parse_many(SAMPLE_CRLF);
        let encoded = encode_many(&pems);

        assert_eq!(SAMPLE_CRLF, encoded);
    }

    #[test]
    fn test_encode_config_contents() {
        let pem = Pem {
            tag: String::from("FOO"),
            contents: vec![1, 2, 3, 4],
        };
        let config = EncodeConfig {
            line_ending: LineEnding::Lf,
        };
        let encoded = encode_config(&pem, config);
        assert!(encoded != "");

        let pem_out = parse(&encoded).unwrap();
        assert_eq!(&pem, &pem_out);
    }

    #[test]
    fn test_encode_many_config() {
        let pems = parse_many(SAMPLE_LF);
        let config = EncodeConfig {
            line_ending: LineEnding::Lf,
        };
        let encoded = encode_many_config(&pems, config);

        assert_eq!(SAMPLE_LF, encoded);
    }
}
