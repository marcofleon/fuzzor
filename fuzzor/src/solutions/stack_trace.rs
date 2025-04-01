use sha1::{Digest, Sha1};

pub trait StackTrace: Sized {
    type Frame: std::fmt::Display;

    fn parse(trace: &str) -> Option<Self>;

    fn frames(&self) -> Vec<Self::Frame>;

    fn hash(&self) -> String {
        let mut hasher = Sha1::new();
        for frame in self.frames() {
            hasher.update(frame.to_string().as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

pub struct LibFuzzerStackTrace {
    frames: Vec<String>,
}

impl StackTrace for LibFuzzerStackTrace {
    type Frame = String;

    fn parse(trace: &str) -> Option<Self> {
        let mut frames = Vec::new();
        let mut entered_trace = false;

        for line in trace.lines() {
            if line.contains("runtime error:")
                || line.contains("==ERROR")
                || line.contains("== ERROR")
                || line.contains("==WARNING")
            {
                entered_trace = true;
            }

            if entered_trace && line.starts_with("SUMMARY") && !frames.is_empty() {
                return Some(Self { frames });
            }

            if entered_trace && line.trim().starts_with('#') {
                let trace_split = balanced_bracket_split(line, ' ');
                if trace_split.len() > 3 && trace_split[2] == "in" {
                    frames.push(trace_split[3].to_string());
                }
            }
        }

        None
    }

    fn frames(&self) -> Vec<Self::Frame> {
        self.frames.clone()
    }
}

// Split a string by `delim` while also ensuring that each split has an equal number of '(' and
// ')' characters.
//
// # Examples
//
// ```
// use fuzzor::solutions::balanced_bracket_split;
// assert_eq!(balanced_bracket_split("test_fn(const Foo&) ()", ' '), &["test_fn(const Foo&)", "()"]);
// ```
fn balanced_bracket_split(input: &str, delim: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut balance_parentheses = 0;
    let mut start = 0;

    for (i, c) in input.char_indices() {
        match c {
            '(' => balance_parentheses += 1,
            ')' => balance_parentheses -= 1,
            _ if c == delim && balance_parentheses == 0 => {
                if i > start {
                    result.push(&input[start..i]);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    // Include the last part if there's any
    if start < input.len() {
        result.push(&input[start..]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brace_split() {
        assert_eq!(
            balanced_bracket_split("test_fn(const Foo&) ()", ' '),
            &["test_fn(const Foo&)", "()"]
        );
        assert_eq!(balanced_bracket_split("( ) ()", ' '), &["( )", "()"]);
        assert_eq!(balanced_bracket_split("( () )", ' '), &["( () )"]);

        assert_eq!(
            balanced_bracket_split("#9 0xaaaac977bac8 in (anonymous namespace)::tx_package_eval_fuzz_target(Span<unsigned char const>) package_eval.cpp", ' '),
            &[
                "#9",
                "0xaaaac977bac8",
                "in",
                "(anonymous namespace)::tx_package_eval_fuzz_target(Span<unsigned char const>)",
                "package_eval.cpp"
            ]
        );

        assert_eq!(
            balanced_bracket_split(
                "#2 0xaaaac942ab5c in fuzzer::Fuzzer::CrashCallback() crtstuff.c",
                ' '
            ),
            &[
                "#2",
                "0xaaaac942ab5c",
                "in",
                "fuzzer::Fuzzer::CrashCallback()",
                "crtstuff.c"
            ]
        );
    }
}
