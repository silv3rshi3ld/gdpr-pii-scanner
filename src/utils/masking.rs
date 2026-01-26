/// PII masking utilities for safe display and logging

/// Mask a PII value for display
///
/// Shows first 3 and last 2 characters, masks the middle
/// Examples:
/// - "123456789" → "123****89"
/// - "NL91ABNA0417164300" → "NL9************00"
/// - "user@example.com" → "use*********com"
pub fn mask_value(value: &str) -> String {
    let len = value.len();

    if len <= 5 {
        // Too short to mask meaningfully
        return "*".repeat(len);
    }

    let show_start = 3.min(len / 3);
    let show_end = 2.min(len / 4);
    let mask_len = len - show_start - show_end;

    format!(
        "{}{}{}",
        &value[..show_start],
        "*".repeat(mask_len),
        &value[len - show_end..]
    )
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

/// Mask email address (show first char + domain)
///
/// Examples:
/// - "john.doe@example.com" → "j********@example.com"
/// - "admin@company.co.uk" → "a****@company.co.uk"
pub fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let local = &email[..at_pos];
        let domain = &email[at_pos..];

        if local.is_empty() {
            return email.to_string();
        }

        let show_chars = 1.min(local.len());
        let mask_len = local.len() - show_chars;

        format!("{}{}{}", &local[..show_chars], "*".repeat(mask_len), domain)
    } else {
        // Invalid email, mask everything
        "*".repeat(email.len())
    }
}

/// Mask IBAN (show country code + last 4)
///
/// Examples:
/// - "NL91ABNA0417164300" → "NL**************4300"
/// - "DE89370400440532013000" → "DE******************3000"
pub fn mask_iban(iban: &str) -> String {
    let clean: String = iban.chars().filter(|c| !c.is_whitespace()).collect();
    let len = clean.len();

    if len < 6 {
        return "*".repeat(len);
    }

    let country = &clean[..2];
    let last_four = &clean[len - 4..];
    let mask_len = len - 6;

    format!("{}{}{}", country, "*".repeat(mask_len), last_four)
}

/// Mask phone number (show country code + last 3)
///
/// Examples:
/// - "+31612345678" → "+31********678"
/// - "0612345678" → "06*******678"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("123456789"), "123****89");
        assert_eq!(mask_value("ABC"), "***");
        assert_eq!(mask_value("ABCDEFGHIJ"), "ABC*****IJ");
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
        assert_eq!(mask_email("a@b.com"), "a@b.com");
        assert_eq!(mask_email("admin@company.co.uk"), "a****@company.co.uk");
    }

    #[test]
    fn test_mask_iban() {
        assert_eq!(mask_iban("NL91ABNA0417164300"), "NL************4300");
        assert_eq!(
            mask_iban("DE89370400440532013000"),
            "DE****************3000"
        );
        assert_eq!(mask_iban("NL91 ABNA 0417 1643 00"), "NL************4300");
    }

    #[test]
    fn test_mask_phone() {
        assert_eq!(mask_phone("+31612345678"), "+31******678");
        assert_eq!(mask_phone("0612345678"), "06*****678");
        assert_eq!(mask_phone("+44 20 1234 5678"), "+44*******678");
    }
}
