//! Server-side password strength rules.
//!
//! The same rules already exist in the web front end (`frontary`), but a client
//! cannot enforce anything: a request sent straight to the GraphQL endpoint
//! bypasses the browser entirely. These checks mirror the front end's so that
//! the two agree on what a password must look like.

use passwords::analyzer;

/// Minimum password length, matching `frontary`'s `cc-password` profile.
const MIN_LEN: usize = 9;

/// Length of a keyboard run that is too guessable to allow, e.g. `qwer`.
const MAX_ADJACENT_RUN: usize = 4;

/// Keyboard rows scanned for adjacent runs, forwards and backwards.
const KEYBOARD_ROWS: [&str; 7] = [
    "1234567890",
    "qwertyuiop",
    "QWERTYUIOP",
    "asdfghjkl",
    "ASDFGHJKL",
    "zxcvbnm",
    "ZXCVBNM",
];

/// Rejects a password that does not meet the strength rules.
///
/// # Errors
///
/// Returns a message naming the unmet rule.
pub(super) fn validate_password_strength(password: &str) -> Result<(), String> {
    let analyzed = analyzer::analyze(password);

    if password != analyzed.password() {
        return Err("password must not contain control characters".to_string());
    }
    if analyzed.spaces_count() > 0 {
        return Err("password must not contain spaces".to_string());
    }
    if analyzed.length() < MIN_LEN {
        return Err(format!("password must be at least {MIN_LEN} characters long"));
    }
    if analyzed.lowercase_letters_count() == 0 {
        return Err("password must contain a lowercase letter".to_string());
    }
    if analyzed.uppercase_letters_count() == 0 {
        return Err("password must contain an uppercase letter".to_string());
    }
    if analyzed.numbers_count() == 0 {
        return Err("password must contain a digit".to_string());
    }
    if analyzed.symbols_count() == 0 {
        return Err("password must contain a symbol".to_string());
    }
    if analyzed.consecutive_count() > 0 {
        return Err("password must not repeat a character consecutively".to_string());
    }
    if has_adjacent_run(password) {
        return Err(format!(
            "password must not contain {MAX_ADJACENT_RUN} adjacent keyboard characters"
        ));
    }
    Ok(())
}

/// Reports whether `password` contains a run of adjacent keyboard characters,
/// in either direction.
fn has_adjacent_run(password: &str) -> bool {
    KEYBOARD_ROWS.iter().any(|row| {
        let reversed: String = row.chars().rev().collect();
        [*row, reversed.as_str()].iter().any(|seq| {
            seq.as_bytes()
                .windows(MAX_ADJACENT_RUN)
                .filter_map(|w| std::str::from_utf8(w).ok())
                .any(|run| password.contains(run))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::validate_password_strength as check;

    #[test]
    fn accepts_a_strong_password() {
        assert!(check("Gyd-Fj8BYKcWg?K9").is_ok());
        assert!(check("xhHGyXw7Gxy%adMC").is_ok());
    }

    #[test]
    fn rejects_what_the_server_used_to_accept() {
        // Every one of these was accepted before the strength rules existed.
        for weak in ["a", "1234", "kisa1", "password"] {
            assert!(check(weak).is_err(), "{weak} should be rejected");
        }
    }

    #[test]
    fn rejects_each_unmet_rule() {
        assert!(check("Sh0rt!Ab").is_err()); // 8 chars, one short
        assert!(check("NOLOWER1!X").is_err()); // no lowercase
        assert!(check("nouppercase1!x").is_err()); // no uppercase
        assert!(check("NoDigitsHere!x").is_err()); // no digit
        assert!(check("NoSymbolHere1x").is_err()); // no symbol
        assert!(check("Has Space1!x").is_err()); // space
        assert!(check("Repeatt1!xY").is_err()); // consecutive repeat
    }

    #[test]
    fn rejects_keyboard_runs_in_both_directions() {
        assert!(check("Xqwer1!aZ").is_err());
        assert!(check("Xrewq1!aZ").is_err());
        assert!(check("X1234!aZb").is_err());
    }
}
