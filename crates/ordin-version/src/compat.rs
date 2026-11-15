// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The compatible-with operator, `~` in dependencies.

use crate::Version;

impl Version {
    /// The lowest version that is no longer compatible with `self` under
    /// the `~` operator. It works like semver's caret: the first non-zero
    /// number of the upstream version goes up by one, and everything after
    /// it is dropped.
    ///
    /// | Base | Compatible up to (not including) |
    /// | --- | --- |
    /// | `~1.27` | `2~` |
    /// | `~0.4` | `0.5~` |
    /// | `~0.0.3` | `0.0.4~` |
    /// | `~0` | `1~` |
    ///
    /// The bound ends in `~`, so pre-releases of the next version (`2~rc1`)
    /// are not compatible. The epoch stays the same, so a version with a
    /// higher epoch never is.
    ///
    /// Only the leading numbers of the upstream version count (`1.27` in
    /// `1.27a~rc1`).
    #[must_use]
    pub fn compatible_bound(&self) -> Self {
        let mut numbers = leading_numbers(self.upstream());
        let bump = numbers
            .iter()
            .position(|n| n != "0")
            .unwrap_or(numbers.len().saturating_sub(1));
        numbers.truncate(bump + 1);
        if let Some(last) = numbers.last_mut() {
            *last = increment(last);
        }
        let mut upstream = numbers.join(".");
        upstream.push('~');
        Self::bound(self.epoch(), upstream)
    }

    /// Whether `self` satisfies `~base`: at least `base`, and below
    /// [`base.compatible_bound()`](Self::compatible_bound).
    #[must_use]
    pub fn is_compatible_with(&self, base: &Self) -> bool {
        self >= base && *self < base.compatible_bound()
    }
}

/// The dot-separated numbers a version starts with, without leading
/// zeros. A valid upstream version starts with a digit, so there is at
/// least one.
fn leading_numbers(upstream: &str) -> Vec<String> {
    let mut numbers = Vec::new();
    let mut rest = upstream;
    loop {
        let len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let (digits, after) = rest.split_at_checked(len).unwrap_or((rest, ""));
        if digits.is_empty() {
            break;
        }
        let trimmed = digits.trim_start_matches('0');
        numbers.push(if trimmed.is_empty() { "0" } else { trimmed }.to_owned());
        // After a dot, the next pass stops by itself if no digits follow.
        match after.strip_prefix('.') {
            Some(next) => rest = next,
            None => break,
        }
    }
    if numbers.is_empty() {
        numbers.push("0".to_owned());
    }
    numbers
}

/// Adds one to a decimal number of any size.
fn increment(number: &str) -> String {
    let mut digits: Vec<u8> = number.bytes().collect();
    for d in digits.iter_mut().rev() {
        if *d == b'9' {
            *d = b'0';
        } else {
            *d += 1;
            return String::from_utf8_lossy(&digits).into_owned();
        }
    }
    let mut out = String::with_capacity(digits.len() + 1);
    out.push('1');
    out.push_str(&String::from_utf8_lossy(&digits));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn the_first_non_zero_number_goes_up() {
        for (base, bound) in [
            ("1.27", "2~"),
            ("1.27.3-2+u1", "2~"),
            ("0.4", "0.5~"),
            ("0.4.7", "0.5~"),
            ("0.0.3", "0.0.4~"),
            ("0", "1~"),
            ("0.0", "0.1~"),
            ("00.07", "0.8~"),
            ("9.1", "10~"),
            ("1.27a~rc1", "2~"),
            ("3.", "4~"),
            ("2:1.5", "2:2~"),
        ] {
            assert_eq!(v(base).compatible_bound().to_string(), bound, "{base}");
        }
    }

    #[test]
    fn compatible_means_at_least_the_base_and_below_the_bound() {
        let base = v("1.27");
        for yes in ["1.27", "1.27-1", "1.27.1", "1.99", "1.999^git1"] {
            assert!(v(yes).is_compatible_with(&base), "{yes} ~1.27");
        }
        for no in ["1.26", "1.27~rc1", "2~rc1", "2", "2.0", "1:1.28"] {
            assert!(!v(no).is_compatible_with(&base), "{no} ~1.27");
        }
        let zero = v("0.4");
        assert!(v("0.4.9").is_compatible_with(&zero));
        assert!(!v("0.5").is_compatible_with(&zero));
        assert!(!v("0.5~rc1").is_compatible_with(&zero));
    }

    #[test]
    fn numbers_of_any_size_increment() {
        assert_eq!(increment("0"), "1");
        assert_eq!(increment("9"), "10");
        assert_eq!(increment("1299"), "1300");
        assert_eq!(increment("99999999999999999999"), "100000000000000000000");
    }

    #[test]
    fn leading_numbers_stop_at_anything_else() {
        assert_eq!(leading_numbers("1.2.3"), ["1", "2", "3"]);
        assert_eq!(leading_numbers("1.2a.3"), ["1", "2"]);
        assert_eq!(leading_numbers("1.2.x"), ["1", "2"]);
        assert_eq!(leading_numbers("007"), ["7"]);
        assert_eq!(leading_numbers("x"), ["0"]);
    }
}
