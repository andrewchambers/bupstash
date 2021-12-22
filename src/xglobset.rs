// EXtended globset functionality
//
// Waiting for https://github.com/BurntSushi/ripgrep/pull/2061 to get merged

use std::ops::Deref;
use std::{fmt, hash};

// Escape metacharacters within the given string by surrounding them in
// brackets. The resulting string will, when compiled into a `Glob`,
// match the input string and nothing else.
pub fn escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // note that ! does not need escaping because it is only special
            // inside brackets
            '?' | '*' | '[' | ']' => {
                escaped.push('[');
                escaped.push(c);
                escaped.push(']');
            }
            c => {
                escaped.push(c);
            }
        }
    }
    escaped
}

// Newtype wrapper around [globset::GlobMatcher] that adds a few trait implementations we absolutely need
#[derive(Clone, Debug)]
pub struct GlobMatcher(globset::GlobMatcher);

impl PartialEq for GlobMatcher {
    fn eq(&self, other: &GlobMatcher) -> bool {
        self.glob() == other.glob()
    }
}

impl Eq for GlobMatcher {}

impl hash::Hash for GlobMatcher {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.glob().hash(state);
    }
}

impl fmt::Display for GlobMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.glob().fmt(f)
    }
}

/* Conversion traits between the wrapped type and back */

impl Deref for GlobMatcher {
    type Target = globset::GlobMatcher;

    fn deref(&self) -> &globset::GlobMatcher {
        &self.0
    }
}

impl From<GlobMatcher> for globset::GlobMatcher {
    fn from(outer: GlobMatcher) -> Self {
        outer.0
    }
}

impl From<globset::GlobMatcher> for GlobMatcher {
    fn from(inner: globset::GlobMatcher) -> Self {
        Self(inner)
    }
}
