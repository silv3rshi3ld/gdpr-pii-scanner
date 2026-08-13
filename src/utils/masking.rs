//! PII masking utilities for safe display and logging

/// Mask a PII value for display
///
/// Shows up to the first 3 and last 2 characters, and masks the middle.
/// Examples:
/// - "123456789" → "123****89"
/// - "ABCDEFGHIJ" → "ABC*****IJ"
pub fn mask_value(value: &str) -> String {
    let len = value.chars().count();

    if len <= 5 {
        // Too short to mask meaningfully
        return "*".repeat(len);
    }

    let show_start = 3.min(len / 3);
    let show_end = 2.min(len / 4);
    let mask_len = len - show_start - show_end;

    let start: String = value.chars().take(show_start).collect();
    let end: String = value
        .chars()
        .rev()
        .take(show_end)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    format!("{start}{}{end}", "*".repeat(mask_len))
}

/// Mask credit card number (show last 4 digits only)
///
/// Examples:
/// - "4532015112830366" → "************0366"
/// - "5425233430109903" → "************9903"
pub fn mask_credit_card(value: &str) -> String {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    let len = digits.len();

    if len < 13 {
        return "*".repeat(len);
    }

    format!("{}{}", "*".repeat(len - 4), &digits[len - 4..])
}

/// Mask email address (show at most the first local-part character + domain)
///
/// Examples:
/// - "john.doe@example.com" → "j*******@example.com"
/// - "admin@company.co.uk" → "a****@company.co.uk"
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];
        let local_len = local.chars().count();

        if local_len == 0 {
            return "*".repeat(email.chars().count());
        }

        // Very short local parts contain no safe character to reveal. Masking
        // two scalars also covers a common decomposed one-grapheme spelling.
        if local_len <= 2 {
            return format!("{}{domain}", "*".repeat(local_len));
        }

        let first = local.chars().next().expect("non-empty local part");
        format!("{first}{}{domain}", "*".repeat(local_len - 1))
    } else {
        // Invalid email, mask everything
        "*".repeat(email.chars().count())
    }
}

/// Mask IBAN (show country code + last 4)
///
/// Examples:
/// - "NL91ABNA0417164300" → "NL************4300"
/// - "DE89370400440532013000" → "DE****************3000"
pub fn mask_iban(iban: &str) -> String {
    let clean: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
    let len = clean.chars().count();

    if len < 6 {
        return "*".repeat(len);
    }

    let country: String = clean.chars().take(2).collect();
    let last_four: String = clean
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mask_len = len - 6;

    format!("{}{}{}", country, "*".repeat(mask_len), last_four)
}

/// Mask phone number (show country code + last 3)
///
/// Examples:
/// - "+31612345678" → "+31******678"
/// - "0612345678" → "06*****678"
pub fn mask_phone(phone: &str) -> String {
    let digits: String = phone
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();
    let len = digits.len();

    if len < 6 {
        return "*".repeat(len);
    }

    let show_start = if digits.starts_with('+') { 3 } else { 2 };
    let show_end = 3;
    let mask_len = len - show_start - show_end;

    format!(
        "{}{}{}",
        &digits[..show_start],
        "*".repeat(mask_len),
        &digits[len - show_end..]
    )
}

/// Mask API key or secret (show first 4-8 chars depending on prefix, mask the rest)
///
/// Examples:
/// - "AKIAIOSFODNN7EXAMPLE" → "AKIA****************"
/// - "sk_live_abcdefghijklmnop" → "sk_live_****************"
pub fn mask_api_key(key: &str) -> String {
    let len = key.chars().count();

    if len <= 8 {
        return "*".repeat(len);
    }

    // Check for known prefixes
    let show_chars = if key.starts_with("sk_live_")
        || key.starts_with("pk_live_")
        || key.starts_with("rk_live_")
    {
        8
    } else if key.starts_with("sk-") || key.starts_with("xox") {
        3
    } else if key.starts_with("AKIA")
        || key.starts_with("ghp_")
        || key.starts_with("ghs_")
        || key.starts_with("gho_")
        || key.starts_with("AIza")
    {
        4
    } else {
        4.min(len / 4)
    };

    let mask_len = len - show_chars;
    let visible: String = key.chars().take(show_chars).collect();
    format!("{}{}", visible, "*".repeat(mask_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("123456789"), "123****89");
        assert_eq!(mask_value("ABC"), "***");
        assert_eq!(mask_value("ABCDEFGHIJ"), "ABC*****IJ");
        assert_eq!(mask_value("éèêëçà"), "éè***à");
        assert_eq!(mask_value("😀12345"), "😀1***5");
    }

    #[test]
    fn test_mask_credit_card() {
        assert_eq!(mask_credit_card("4532015112830366"), "************0366");
        assert_eq!(mask_credit_card("5425233430109903"), "************9903");
        assert_eq!(mask_credit_card("4532 0151 1283 0366"), "************0366");
    }

    #[test]
    fn test_mask_email() {
        assert_eq!(mask_email("john.doe@example.com"), "j*******@example.com");
        assert_eq!(mask_email("a@b.com"), "*@b.com");
        assert_eq!(mask_email("ab@b.com"), "**@b.com");
        assert_eq!(mask_email("admin@company.co.uk"), "a****@company.co.uk");
        assert_eq!(mask_email("éclair@example.com"), "é*****@example.com");
        assert_eq!(mask_email("😀@example.com"), "*@example.com");
        assert_eq!(mask_email("e\u{301}@example.com"), "**@example.com");
        assert_eq!(mask_email("@example.com"), "************");
        assert_eq!(mask_email("😀"), "*");
    }

    #[test]
    fn test_mask_iban() {
        assert_eq!(mask_iban("NL91ABNA0417164300"), "NL************4300");
        assert_eq!(
            mask_iban("DE89370400440532013000"),
            "DE****************3000"
        );
        assert_eq!(mask_iban("NL91 ABNA 0417 1643 00"), "NL************4300");
        assert_eq!(mask_iban("ÉU123456"), "ÉU**3456");
    }

    #[test]
    fn test_mask_phone() {
        assert_eq!(mask_phone("+31612345678"), "+31******678");
        assert_eq!(mask_phone("0612345678"), "06*****678");
        assert_eq!(mask_phone("+44 20 1234 5678"), "+44*******678");
    }

    #[test]
    fn test_mask_api_key() {
        assert_eq!(mask_api_key("AKIAIOSFODNN7EXAMPLE"), "AKIA****************");
        assert_eq!(
            mask_api_key("sk_live_abcdefghijklmnop"),
            "sk_live_****************"
        );
        assert_eq!(
            mask_api_key("ghp_1234567890abcdefghijklmnopqrstu123456"),
            "ghp_*************************************"
        );
        assert_eq!(
            mask_api_key("sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"),
            "sk-************************************************"
        );
        assert_eq!(
            mask_api_key("xoxb-1234567890-abcdefghijk"),
            "xox************************"
        );
        assert_eq!(mask_api_key("éèêëçà1234"), "éè********");
    }
}
