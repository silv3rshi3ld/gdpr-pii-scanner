/// Entropy calculation utilities voor detectie van high-entropy strings
/// (zoals API keys, tokens, passwords)
///
/// Shannon entropy wordt gebruikt om te meten hoe "random" een string is.
/// Hoge entropy duidt op cryptografisch materiaal.
use std::collections::HashMap;

/// Bereken Shannon entropy van een string
///
/// Shannon entropy meet de onvoorspelbaarheid van data.
/// Voor een string: H(X) = -Σ(p(x) * log2(p(x)))
///
/// Typische waarden:
/// - "aaaaaaa" → ~0.0 (geen entropy)
/// - "abcdefg" → ~2.8 (lage entropy)
/// - "aK9$mP3" → ~3.8 (medium entropy)
/// - Random Base64 → ~6.0 (hoge entropy)
///
/// # Voorbeelden
/// ```
/// use pii_radar::utils::entropy::shannon_entropy;
///
/// assert!(shannon_entropy("aaaaaaa") < 1.0);
/// assert!(shannon_entropy("aK9$mP3zQ!vX2") > 3.5);
/// ```
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    // Tel frequentie van elk karakter
    let mut frequencies: HashMap<char, usize> = HashMap::new();
    for c in text.chars() {
        *frequencies.entry(c).or_insert(0) += 1;
    }

    let len = text.len() as f64;

    // Bereken entropy: -Σ(p(x) * log2(p(x)))
    let entropy: f64 = frequencies
        .values()
        .map(|&count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum();

    entropy
}

/// Check of een string high-entropy is (waarschijnlijk een secret)
///
/// Thresholds:
/// - < 3.5: Low entropy (waarschijnlijk geen secret)
/// - 3.5 - 4.5: Medium entropy (mogelijk secret)
/// - > 4.5: High entropy (waarschijnlijk secret)
pub fn is_high_entropy(text: &str, threshold: f64) -> bool {
    shannon_entropy(text) >= threshold
}

/// Bereken entropy voor Base64-encoded strings (hogere threshold)
pub fn is_high_entropy_base64(text: &str) -> bool {
    // Base64 heeft natuurlijk hogere entropy
    // Threshold iets hoger: ~4.5
    is_high_entropy(text, 4.5)
}

/// Bereken entropy voor hexadecimale strings
pub fn is_high_entropy_hex(text: &str) -> bool {
    // Hex heeft theoretische max entropy van 4.0 (16 mogelijke karakters)
    // Threshold: ~3.5 voor verdachte strings
    is_high_entropy(text, 3.5)
}

/// Detecteer of een string waarschijnlijk een Base64-encoded secret is
pub fn is_likely_base64_secret(text: &str) -> bool {
    // Check:
    // 1. Lengte > 20 karakters (te kort is waarschijnlijk geen key)
    // 2. Bevat Base64 karakters
    // 3. High entropy

    if text.len() < 20 {
        return false;
    }

    // Check of alle karakters Base64 zijn
    let is_base64_chars = text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

    if !is_base64_chars {
        return false;
    }

    // Check entropy
    is_high_entropy_base64(text)
}

/// Detecteer of een string waarschijnlijk een hex-encoded secret is
pub fn is_likely_hex_secret(text: &str) -> bool {
    // Check:
    // 1. Lengte > 32 karakters (256-bit key)
    // 2. Alleen hex karakters
    // 3. High entropy voor hex

    if text.len() < 32 {
        return false;
    }

    // Check of alle karakters hex zijn
    let is_hex_chars = text.chars().all(|c| c.is_ascii_hexdigit());

    if !is_hex_chars {
        return false;
    }

    // Check entropy
    is_high_entropy_hex(text)
}

/// Bereken een "randomness score" van 0-10
/// Gebruikt voor ranking van potentiële secrets
pub fn randomness_score(text: &str) -> u8 {
    let entropy = shannon_entropy(text);
    let length = text.len();

    // Score gebaseerd op entropy en lengte
    let entropy_score = (entropy / 6.0 * 5.0) as u8; // Max 5 punten voor entropy
    let length_score = if length >= 32 {
        3
    } else if length >= 20 {
        2
    } else {
        1
    }; // Max 3 punten voor lengte

    // Bonus voor mixed case en special characters
    let has_upper = text.chars().any(|c| c.is_uppercase());
    let has_lower = text.chars().any(|c| c.is_lowercase());
    let has_digit = text.chars().any(|c| c.is_ascii_digit());
    let has_special = text.chars().any(|c| !c.is_alphanumeric());

    let complexity_score = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count() as u8; // Max 4 punten

    // Maar niet meer dan 10 totaal
    (entropy_score + length_score + complexity_score).min(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_low() {
        assert!(shannon_entropy("aaaaaaa") < 0.1);
        assert!(shannon_entropy("1111111") < 0.1);
    }

    #[test]
    fn test_shannon_entropy_medium() {
        let entropy = shannon_entropy("abcdefg");
        assert!(entropy > 2.5 && entropy < 3.5);
    }

    #[test]
    fn test_shannon_entropy_high() {
        // Random-looking string
        let entropy = shannon_entropy("aK9$mP3zQ!vX2");
        assert!(entropy > 3.5);
    }

    #[test]
    fn test_shannon_entropy_base64() {
        // Typical Base64 encoded data has high entropy
        let base64 = "dGhpcyBpcyBhIHRlc3Q="; // "this is a test" encoded
        let entropy = shannon_entropy(base64);
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_is_high_entropy() {
        assert!(!is_high_entropy("hello", 4.0));
        assert!(is_high_entropy("aK9$mP3zQ!vX2", 3.5));
    }

    #[test]
    fn test_is_likely_base64_secret() {
        // Real API key pattern
        assert!(is_likely_base64_secret(
            "dGhpc2lzYXZlcnlsb25nYmFzZTY0ZW5jb2RlZHNlY3JldGtleQ=="
        ));

        // Too short
        assert!(!is_likely_base64_secret("dGVzdA=="));

        // Not base64 characters
        assert!(!is_likely_base64_secret("this-is-not-base64-at-all!"));
    }

    #[test]
    fn test_is_likely_hex_secret() {
        // 256-bit hex key
        assert!(is_likely_hex_secret(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        ));

        // Too short
        assert!(!is_likely_hex_secret("a1b2c3d4"));

        // Not hex
        assert!(!is_likely_hex_secret("this-is-not-hex-at-all-12345"));
    }

    #[test]
    fn test_randomness_score() {
        // Low randomness
        assert!(randomness_score("aaaaaaa") <= 3);

        // Medium randomness
        let medium_score = randomness_score("password123");
        assert!(medium_score >= 3 && medium_score <= 6);

        // High randomness
        let high_score = randomness_score("aK9$mP3zQ!vX2rT8nB5wL4");
        assert!(high_score >= 7);
    }

    #[test]
    fn test_randomness_score_boundaries() {
        // Score should never exceed 10
        let max_random = "aK9$mP3zQ!vX2rT8nB5wL4jN7mR9pS6uV3wY8zA1bC4dE7fG0hI2jK5lM8nO1pQ4rS7tU0vW3xY6zA9bC2dE5fG8hI1jK4lM7nO0pQ3rS6";
        assert!(randomness_score(max_random) <= 10);

        // Empty string
        assert_eq!(randomness_score(""), 1); // Minimum score
    }
}
