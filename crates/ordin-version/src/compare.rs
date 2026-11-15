// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 The Ordin Authors

//! The text comparison at the heart of the universal ordering: Debian's
//! algorithm (dpkg's `verrevcmp`), extended with rpm's `^`.

use core::cmp::Ordering;

/// Compares two pieces of version text, such as two upstream versions or
/// two releases, with Ordin's universal ordering.
///
/// The text is split into alternating runs of non-digits and digits.
/// Non-digit runs compare character by character: `~` sorts before
/// everything (even the end of the text), then the end of the text, then
/// `^`, then letters, then every other character. Digit runs compare as
/// numbers, so `1.10` sorts after `1.9` and `01` equals `1`.
///
/// Without `^` this is exactly dpkg's ordering. `^` works as in rpm: it
/// sorts after the end of the text but before anything that continues it,
/// so `1.2` < `1.2^git1` < `1.2.1`. One difference from rpm remains: as in
/// dpkg, a digit at the start of a number run compares like the end of the
/// text, so `a^` sorts after `a1`. Versions don't put a caret straight
/// after a letter where a number could follow, so this never matters in
/// practice.
///
/// Any text can be compared, valid or not, and the result is always a
/// total order.
#[must_use]
pub fn compare_text(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    while !a.is_empty() || !b.is_empty() {
        // The non-digit run, one character at a time.
        while is_non_digit(a.first()) || is_non_digit(b.first()) {
            let order = weight(a.first().copied()).cmp(&weight(b.first().copied()));
            if order != Ordering::Equal {
                return order;
            }
            // Equal characters in a non-digit run are present on both
            // sides (an end or a digit never equals a non-digit), so both
            // advance by one.
            a = a.get(1..).unwrap_or_default();
            b = b.get(1..).unwrap_or_default();
        }
        // The digit run, as a number.
        let (zeros_a, end_a) = digit_run(a);
        let (zeros_b, end_b) = digit_run(b);
        let order = compare_numbers(
            a.get(zeros_a..end_a).unwrap_or_default(),
            b.get(zeros_b..end_b).unwrap_or_default(),
        );
        if order != Ordering::Equal {
            return order;
        }
        a = a.get(end_a..).unwrap_or_default();
        b = b.get(end_b..).unwrap_or_default();
    }
    Ordering::Equal
}

fn is_non_digit(c: Option<&u8>) -> bool {
    c.is_some_and(|c| !c.is_ascii_digit())
}

/// dpkg's `order()` with `^` added: `~` first, then the end of the text
/// (and a digit, which ends a non-digit run), then `^`, then letters, then
/// everything else.
///
/// `^` is just one more weight, so the ordering stays a total order.
/// Treating it specially against a digit would not: dpkg makes a digit run
/// of 0 equal to no digit run at all, so `^` must compare with a digit the
/// way it compares with the end.
fn weight(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(b'^') => 1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

/// Measures the run of digits at the start of `text`: how many of them are
/// leading zeros, and where the run ends.
///
/// It returns lengths rather than slices on purpose. Mutation testing
/// replaces a function's result with arbitrary values, and a slice result
/// can be replaced with freshly leaked memory; inside `compare_text`'s
/// loop that leaks without end and exhausted the test machine's memory.
/// Lengths can only make the loop wrong or endless, which the tests and
/// the timeout catch.
fn digit_run(text: &[u8]) -> (usize, usize) {
    let zeros = text.iter().take_while(|&&c| c == b'0').count();
    let digits = text.iter().take_while(|c| c.is_ascii_digit()).count();
    (zeros, digits)
}

/// Compares two runs of digits without leading zeros as numbers of any
/// size: the longer one is larger, and runs of equal length compare digit
/// by digit.
fn compare_numbers(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::{Equal, Greater, Less};

    /// Every pair in `ascending` is checked both ways: earlier entries are
    /// less than later ones.
    fn assert_ascending(ascending: &[&str]) {
        for (i, a) in ascending.iter().enumerate() {
            assert_eq!(compare_text(a, a), Equal, "{a} = {a}");
            for b in &ascending[i + 1..] {
                assert_eq!(compare_text(a, b), Less, "{a} < {b}");
                assert_eq!(compare_text(b, a), Greater, "{b} > {a}");
            }
        }
    }

    #[test]
    fn numbers_compare_as_numbers() {
        assert_ascending(&["1", "1.2", "1.9", "1.10", "1.100", "2", "10"]);
        assert_eq!(compare_text("1.01", "1.1"), Equal);
        assert_eq!(compare_text("007", "7"), Equal);
        assert_eq!(compare_text("0", "00"), Equal);
        assert_eq!(compare_text("", "0"), Equal);
    }

    #[test]
    fn numbers_of_any_size_compare() {
        let big = "123456789012345678901234567890";
        let bigger = "123456789012345678901234567891";
        assert_eq!(compare_text(big, bigger), Less);
        assert_eq!(compare_text(&format!("1.{big}"), "1.9"), Greater);
    }

    #[test]
    fn tilde_sorts_before_everything() {
        assert_ascending(&["1~~", "1~~a", "1~", "1", "1^", "1a", "1+", "1.0"]);
        assert_ascending(&["1.2~rc1", "1.2~rc2", "1.2"]);
    }

    #[test]
    fn caret_sorts_after_the_end_and_before_anything_else() {
        assert_ascending(&["1.2", "1.2^", "1.2^git1", "1.2^git2", "1.2.0", "1.2.1"]);
        // Before a letter and every other character.
        assert_eq!(compare_text("1.2^", "1.2a"), Less);
        assert_eq!(compare_text("1^", "1a.0"), Less);
        // A digit compares like the end, so the caret is above it (see the
        // function's documentation).
        assert_eq!(compare_text("a^", "a1"), Greater);
        assert_eq!(compare_text("^", "0~"), Greater);
        assert_eq!(compare_text("1^", "1+"), Less);
        // After `~`, which sorts before the end.
        assert_eq!(compare_text("1^", "1~"), Greater);
        assert_eq!(compare_text("1~", "1^"), Less);
        // Two carets continue the comparison.
        assert_eq!(compare_text("1^a", "1^b"), Less);
        assert_eq!(compare_text("1^^", "1^"), Greater);
    }

    #[test]
    fn letters_sort_before_other_characters() {
        assert_ascending(&["1", "1A", "1Z", "1a", "1z", "1+", "1-", "1."]);
        assert_eq!(compare_text("1.0a", "1.0+"), Less);
    }

    #[test]
    fn every_other_character_sorts_after_the_end_and_letters() {
        // compare_text accepts any text, so even a control character or a
        // NUL byte must sort after the end of the text and after letters,
        // never tie with the end.
        assert_eq!(compare_text("1\0", "1"), Greater);
        assert_eq!(compare_text("1\0", "1z"), Greater);
        assert_eq!(compare_text("1\u{1}", "1\0"), Greater);
        assert_eq!(compare_text("1é", "1z"), Greater);
    }

    #[test]
    fn debian_examples() {
        assert_ascending(&[
            "1.0~rc1",
            "1.0",
            "1.0a",
            "1.0+dfsg",
            "1.0+dfsg1",
            "1.0.1",
            "1.1",
        ]);
        assert_eq!(compare_text("2.30", "2.4"), Greater);
    }

    #[test]
    fn digit_runs_drop_leading_zeros() {
        assert_eq!(digit_run(b"0012ab"), (2, 4));
        assert_eq!(digit_run(b"000"), (3, 3));
        assert_eq!(digit_run(b"abc"), (0, 0));
        assert_eq!(digit_run(b"120"), (0, 3));
    }
}
