//! Checksum validation utilities voor PII detectie
//!
//! Dit module bevat algoritmes voor:
//!
//! - Nederlandse BSN 11-proef validatie
//! - Luhn algoritme (creditcards)
//! - IBAN modulo-97 validatie
//! - Modulo-10 en modulo-11 checksums

/// Valideert een Nederlands BSN (Burgerservicenummer) met de 11-proef
///
/// De 11-proef is een checksum algoritme waarbij elk cijfer wordt vermenigvuldigd
/// met een aflopende wegingsfactor (9, 8, 7, 6, 5, 4, 3, 2, -1).
/// De som moet deelbaar zijn door 11.
///
/// # Voorbeelden
/// ```
/// use pii_radar::utils::checksum::validate_bsn_11_proef;
///
/// assert!(validate_bsn_11_proef("111222333"));  // Valide BSN
/// assert!(!validate_bsn_11_proef("123456789")); // Invalide BSN
/// ```
pub fn validate_bsn_11_proef(bsn: &str) -> bool {
    // Verwijder alle niet-cijfer karakters (spaties, streepjes)
    let digits: Vec<u32> = bsn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // BSN moet exact 9 cijfers zijn
    if digits.len() != 9 {
        return false;
    }

    // BSN mag niet beginnen met 0 (niet officieel, maar in praktijk niet voorkomend)
    if digits[0] == 0 {
        return false;
    }

    // 11-proef: (9×d1 + 8×d2 + 7×d3 + 6×d4 + 5×d5 + 4×d6 + 3×d7 + 2×d8 - 1×d9) mod 11 = 0
    const WEIGHTS: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];

    let sum: i32 = digits
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(&digit, &weight)| digit as i32 * weight)
        .sum();

    sum % 11 == 0
}

/// Valideert een creditcardnummer met het Luhn algoritme (modulo-10)
///
/// Het Luhn algoritme is een checksum formule die gebruikt wordt voor creditcards,
/// IMEI nummers, en andere identificatienummers.
///
/// Algoritme:
/// 1. Start van rechts (minst significante cijfer)
/// 2. Verdubbel elk tweede cijfer
/// 3. Als het resultaat > 9, trek er 9 vanaf (of: tel de cijfers op)
/// 4. Tel alle cijfers bij elkaar op
/// 5. Als de som deelbaar is door 10, is het nummer valide
///
/// # Voorbeelden
/// ```
/// use pii_radar::utils::checksum::validate_luhn;
///
/// assert!(validate_luhn("4532015112830366"));  // Valide Visa test nummer
/// assert!(!validate_luhn("1234567890123456")); // Invalide
/// ```
pub fn validate_luhn(number: &str) -> bool {
    // Verwijder alle niet-cijfer karakters
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Creditcards zijn tussen 13 en 19 cijfers (meestal 16)
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    // Luhn algoritme: start van rechts, verdubbel elk tweede cijfer
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| {
            if index % 2 == 1 {
                // Verdubbel elk tweede cijfer (van rechts)
                let doubled = digit * 2;
                // Als > 9, trek 9 af (equivalent aan cijfers optellen)
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                digit
            }
        })
        .sum();

    sum.is_multiple_of(10)
}

/// Valideert een IBAN (International Bank Account Number) met modulo-97
///
/// IBAN validatie volgens ISO 13616:
/// 1. Verplaats de eerste 4 karakters naar het einde
/// 2. Vervang letters door cijfers (A=10, B=11, ..., Z=35)
/// 3. Bereken modulo 97
/// 4. Resultaat moet 1 zijn
///
/// # Voorbeelden
/// ```
/// use pii_radar::utils::checksum::validate_iban;
///
/// assert!(validate_iban("NL91ABNA0417164300"));  // Valide Nederlands IBAN
/// assert!(validate_iban("DE89370400440532013000")); // Valide Duits IBAN
/// assert!(!validate_iban("NL00ABNA0000000000")); // Invalide checksum
/// ```
pub fn validate_iban(iban: &str) -> bool {
    // Verwijder alle whitespace
    let iban_clean: String = iban.chars().filter(|c| !c.is_whitespace()).collect();

    // IBAN moet tussen 15 en 34 karakters zijn
    if iban_clean.len() < 15 || iban_clean.len() > 34 {
        return false;
    }

    // Eerste twee karakters moeten letters zijn (landcode)
    let chars: Vec<char> = iban_clean.chars().collect();
    if chars.len() < 4
        || !chars[0].is_ascii_uppercase()
        || !chars[1].is_ascii_uppercase()
        || !chars[2].is_ascii_digit()
        || !chars[3].is_ascii_digit()
    {
        return false;
    }

    // Verplaats eerste 4 karakters naar het einde
    let rearranged = format!("{}{}", &iban_clean[4..], &iban_clean[..4]);

    // Vervang letters door cijfers: A=10, B=11, ..., Z=35
    let numeric: String = rearranged
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                // A=10, dus c as u32 - 'A' as u32 + 10
                ((c as u32) - ('A' as u32) + 10).to_string()
            } else if c.is_ascii_digit() {
                c.to_string()
            } else {
                // Ongeldig karakter
                String::from("X") // Dit zorgt voor een ongeldige IBAN
            }
        })
        .collect();

    // Check of er ongeldige karakters waren
    if numeric.contains('X') {
        return false;
    }

    // Bereken modulo 97 in chunks om integer overflow te voorkomen
    // We kunnen niet het hele nummer in één keer doen vanwege de lengte
    let remainder = numeric.chars().try_fold(0u64, |acc, c| {
        let digit = c.to_digit(10)?;
        Some((acc * 10 + digit as u64) % 97)
    });

    remainder == Some(1)
}

/// Basis modulo-10 checksum
pub fn checksum_mod10(digits: &[u32]) -> u32 {
    digits.iter().sum::<u32>() % 10
}

/// Basis modulo-11 checksum met wegingsfactoren
pub fn checksum_mod11(digits: &[u32], weights: &[i32]) -> i32 {
    if digits.len() != weights.len() {
        return -1; // Ongeldige input
    }

    let sum: i32 = digits
        .iter()
        .zip(weights.iter())
        .map(|(&d, &w)| d as i32 * w)
        .sum();

    sum % 11
}

/// Validates UK NHS Number using modulus 11 algorithm
///
/// NHS numbers are 10 digits with the last digit being a check digit.
/// Algorithm: Multiply first 9 digits by weights (10,9,8,7,6,5,4,3,2),
/// sum them, divide by 11, subtract remainder from 11 = check digit.
/// If result is 11, check digit is 0. If result is 10, number is invalid.
///
/// # Examples
/// ```
/// use pii_radar::validate_nhs_number;
///
/// assert!(validate_nhs_number("9434765919")); // Valid NHS number
/// assert!(!validate_nhs_number("9434765910")); // Invalid check digit
/// ```
pub fn validate_nhs_number(nhs: &str) -> bool {
    // Remove spaces and non-digit characters
    let digits: Vec<u32> = nhs
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Must be exactly 10 digits
    if digits.len() != 10 {
        return false;
    }

    // Weights for first 9 digits
    const WEIGHTS: [u32; 9] = [10, 9, 8, 7, 6, 5, 4, 3, 2];

    // Calculate sum of products
    let sum: u32 = digits[..9]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(&digit, &weight)| digit * weight)
        .sum();

    // Calculate check digit
    let remainder = sum % 11;
    let check_digit = match 11 - remainder {
        11 => 0,            // If result is 11, check digit is 0
        10 => return false, // If result is 10, number is invalid
        n => n,
    };

    // Verify check digit matches
    digits[9] == check_digit
}

/// Validates Spanish DNI/NIE check letter using modulus 23 algorithm
///
/// DNI: 8 digits + 1 check letter
/// NIE: X/Y/Z + 7 digits + 1 check letter (X=0, Y=1, Z=2 for calculation)
///
/// Algorithm: number mod 23, then map to letter using table TRWAGMYFPDXBNJZSQVHLCKE
///
/// # Examples
/// ```
/// use pii_radar::validate_spain_id;
///
/// assert!(validate_spain_id("12345678Z")); // Valid DNI
/// assert!(validate_spain_id("X1234567L")); // Valid NIE
/// ```
pub fn validate_spain_id(id: &str) -> bool {
    const CHECK_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

    let clean = id.to_uppercase().replace([' ', '-'], "");

    if clean.len() != 9 {
        return false;
    }

    let chars: Vec<char> = clean.chars().collect();

    // Extract numeric part and check letter
    let (numeric_str, check_letter) = if chars[0].is_alphabetic() {
        // NIE format: X/Y/Z + 7 digits + letter
        if !matches!(chars[0], 'X' | 'Y' | 'Z') {
            return false;
        }

        // Convert prefix to number: X=0, Y=1, Z=2
        let prefix = match chars[0] {
            'X' => '0',
            'Y' => '1',
            'Z' => '2',
            _ => return false,
        };

        // Check middle 7 characters are digits
        if !chars[1..8].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }

        let num_str: String = std::iter::once(prefix)
            .chain(chars[1..8].iter().copied())
            .collect();
        (num_str, chars[8])
    } else {
        // DNI format: 8 digits + letter
        if !chars[..8].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }

        (chars[..8].iter().collect::<String>(), chars[8])
    };

    // Parse number
    let number: u32 = match numeric_str.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    // Calculate expected check letter
    let index = (number % 23) as usize;
    let expected_letter = CHECK_LETTERS[index] as char;

    check_letter == expected_letter
}

/// Validates Belgian RRN (Rijksregisternummer) using modulus 97 algorithm
///
/// Format: YYMMDD-SSS-CC (11 digits)
/// - YYMMDD: Birth date
/// - SSS: Sequential number (odd=male, even=female)
/// - CC: Check digits (97 - (first 9 digits mod 97))
///
/// For births after 2000, prepend "2" before calculation.
///
/// # Examples
/// ```
/// use pii_radar::validate_belgian_rrn;
///
/// assert!(validate_belgian_rrn("85073000184")); // Valid RRN
/// ```
pub fn validate_belgian_rrn(rrn: &str) -> bool {
    // Remove separators
    let digits: Vec<u32> = rrn
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Must be exactly 11 digits
    if digits.len() != 11 {
        return false;
    }

    // Extract parts
    let date_seq: u64 = digits[..9].iter().fold(0, |acc, &d| acc * 10 + d as u64);
    let check_digits: u32 = digits[9] * 10 + digits[10];

    // Try calculation for pre-2000 birth
    let calculated_pre_2000 = 97 - (date_seq % 97);

    if calculated_pre_2000 as u32 == check_digits {
        return true;
    }

    // Try calculation for post-2000 birth (prepend "2")
    let date_seq_2000 = 2_000_000_000_u64 + date_seq;
    let calculated_post_2000 = 97 - (date_seq_2000 % 97);

    calculated_post_2000 as u32 == check_digits
}

/// Validate German Steueridentifikationsnummer (Tax ID)
///
/// German Tax ID (Steuer-ID) is an 11-digit number with specific rules:
/// 1. Must be exactly 11 digits
/// 2. One digit must appear exactly 2 or 3 times
/// 3. Not all digits can be the same
/// 4. Uses a modified modulus 11 check with product/sum algorithm
///
/// # Algorithm
/// Starting with M=10, for each digit d1-d10:
///
/// 1. S = (d + M) % 10
/// 2. If S == 0, S = 10
/// 3. M = (S * 2) % 11
///
///    Final check: (11 - M) % 10 must equal digit 11
///
/// # Examples
/// ```
/// use pii_radar::utils::checksum::validate_steuer_id;
///
/// assert!(validate_steuer_id("86095742719")); // Valid Steuer-ID
/// ```
pub fn validate_steuer_id(id: &str) -> bool {
    // Remove any separators/spaces
    let digits: Vec<u32> = id
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Must be exactly 11 digits
    if digits.len() != 11 {
        return false;
    }

    // Rule: Not all digits can be the same
    if digits.iter().all(|&d| d == digits[0]) {
        return false;
    }

    // Rule: One digit must appear exactly 2 or 3 times
    let mut freq = [0u8; 10];
    for &d in &digits[..10] {
        // Only check first 10 digits
        freq[d as usize] += 1;
    }

    let has_repeated_digit = freq.iter().any(|&count| count == 2 || count == 3);
    if !has_repeated_digit {
        return false;
    }

    // Modified modulus 11 check (product/sum algorithm)
    let mut m = 10;

    for &d in &digits[..10] {
        // Process first 10 digits
        let mut s = (d + m) % 10;
        if s == 0 {
            s = 10;
        }
        m = (s * 2) % 11;
    }

    // Check digit calculation
    let calculated_check = (11 - m) % 10;

    calculated_check == digits[10]
}

/// Validates a Portuguese NIF (Número de Identificação Fiscal)
///
/// The NIF is a 9-digit tax identification number.
/// Validation algorithm:
/// 1. First digit must be 1, 2, 3, 5, 6, or 9
/// 2. Multiply each of the first 8 digits by (9, 8, 7, 6, 5, 4, 3, 2)
/// 3. Sum the products
/// 4. Check digit = 11 - (sum % 11)
/// 5. If check digit is 10 or 11, it becomes 0
///
/// # Examples
/// ```
/// use pii_radar::utils::checksum::validate_portugal_nif;
///
/// assert!(validate_portugal_nif("123456789"));  // Valid NIF
/// assert!(!validate_portugal_nif("123456780")); // Invalid NIF
/// ```
pub fn validate_portugal_nif(nif: &str) -> bool {
    // Remove non-digit characters
    let digits: Vec<u32> = nif
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    // Must be exactly 9 digits
    if digits.len() != 9 {
        return false;
    }

    // First digit must be 1, 2, 3, 5, 6, or 9
    let first_digit = digits[0];
    if ![1, 2, 3, 5, 6, 9].contains(&first_digit) {
        return false;
    }

    // Calculate checksum using modulus 11
    let multipliers = [9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = digits[..8]
        .iter()
        .zip(multipliers.iter())
        .map(|(d, m)| d * m)
        .sum();

    let remainder = sum % 11;
    let check_digit = if remainder == 0 || remainder == 1 {
        0
    } else {
        11 - remainder
    };

    check_digit == digits[8]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== BSN Tests =====

    #[test]
    fn test_bsn_valid() {
        // Valide BSN nummers (fictief maar wiskundig correct)
        assert!(validate_bsn_11_proef("111222333"));
        assert!(validate_bsn_11_proef("123456782"));
    }

    #[test]
    fn test_bsn_valid_with_formatting() {
        assert!(validate_bsn_11_proef("111-222-333"));
        assert!(validate_bsn_11_proef("111 222 333"));
        assert!(validate_bsn_11_proef("123-45-6782"));
    }

    #[test]
    fn test_bsn_invalid() {
        assert!(!validate_bsn_11_proef("123456789")); // Foutieve checksum
        assert!(!validate_bsn_11_proef("111222334")); // Laatste cijfer fout
        assert!(!validate_bsn_11_proef("000000000")); // Begint met 0
    }

    #[test]
    fn test_bsn_wrong_length() {
        assert!(!validate_bsn_11_proef("12345678")); // Te kort
        assert!(!validate_bsn_11_proef("1234567890")); // Te lang
        assert!(!validate_bsn_11_proef("")); // Leeg
    }

    // ===== Luhn Tests =====

    #[test]
    fn test_luhn_valid_visa() {
        assert!(validate_luhn("4532015112830366")); // Visa test card
        assert!(validate_luhn("4556737586899855")); // Visa
    }

    #[test]
    fn test_luhn_valid_mastercard() {
        assert!(validate_luhn("5425233430109903")); // Mastercard test card
        assert!(validate_luhn("2221000000000009")); // Mastercard 2-series
    }

    #[test]
    fn test_luhn_valid_amex() {
        assert!(validate_luhn("378282246310005")); // Amex (15 digits)
    }

    #[test]
    fn test_luhn_with_spaces() {
        assert!(validate_luhn("4532 0151 1283 0366"));
        assert!(validate_luhn("5425-2334-3010-9903"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!validate_luhn("1234567890123456")); // Foutieve checksum
        assert!(!validate_luhn("4532015112830367")); // Laatste cijfer fout
    }

    #[test]
    fn test_luhn_wrong_length() {
        assert!(!validate_luhn("123456789012")); // Te kort (12 digits)
        assert!(!validate_luhn("12345678901234567890")); // Te lang (20 digits)
    }

    // ===== IBAN Tests =====

    #[test]
    fn test_iban_valid_netherlands() {
        assert!(validate_iban("NL91ABNA0417164300"));
        assert!(validate_iban("NL20INGB0001234567"));
    }

    #[test]
    fn test_iban_valid_germany() {
        assert!(validate_iban("DE89370400440532013000"));
    }

    #[test]
    fn test_iban_valid_belgium() {
        assert!(validate_iban("BE68539007547034"));
    }

    #[test]
    fn test_iban_with_spaces() {
        assert!(validate_iban("NL91 ABNA 0417 1643 00"));
        assert!(validate_iban("DE89 3704 0044 0532 0130 00"));
    }

    #[test]
    fn test_iban_invalid_checksum() {
        assert!(!validate_iban("NL00ABNA0417164300")); // Foutieve checksum
        assert!(!validate_iban("NL91ABNA0417164301")); // Laatste cijfer fout
    }

    #[test]
    fn test_iban_invalid_format() {
        assert!(!validate_iban("XX91ABNA0417164300")); // Geen geldige landcode
        assert!(!validate_iban("NLXABNA0417164300")); // Check cijfers moeten digits zijn
        assert!(!validate_iban("NL91")); // Te kort
    }

    #[test]
    fn test_iban_wrong_length() {
        assert!(!validate_iban("NL91ABNA")); // Te kort
        assert!(!validate_iban("A".repeat(35).as_str())); // Te lang
    }

    // ===== Modulo helper tests =====

    #[test]
    fn test_checksum_mod10() {
        assert_eq!(checksum_mod10(&[1, 2, 3, 4, 5]), 5); // 15 % 10 = 5
        assert_eq!(checksum_mod10(&[9, 9, 9, 9, 9]), 5); // 45 % 10 = 5
    }

    #[test]
    fn test_checksum_mod11() {
        let weights = [9, 8, 7, 6, 5, 4, 3, 2, -1];
        let digits = [1, 1, 1, 2, 2, 2, 3, 3, 3];
        assert_eq!(checksum_mod11(&digits, &weights), 0); // Valide BSN
    }

    // ===== NHS Number Tests =====

    #[test]
    fn test_nhs_valid() {
        assert!(validate_nhs_number("9434765919")); // Valid test number
        assert!(validate_nhs_number("943 476 5919")); // With spaces
    }

    #[test]
    fn test_nhs_invalid_checksum() {
        assert!(!validate_nhs_number("9434765910")); // Wrong check digit
        assert!(!validate_nhs_number("1234567890")); // Invalid
    }

    #[test]
    fn test_nhs_wrong_length() {
        assert!(!validate_nhs_number("123456789")); // Too short
        assert!(!validate_nhs_number("12345678901")); // Too long
    }

    // ===== Spain DNI/NIE Tests =====

    #[test]
    fn test_spain_dni_valid() {
        assert!(validate_spain_id("12345678Z")); // Valid DNI
        assert!(validate_spain_id("87654321X")); // Valid DNI
    }

    #[test]
    fn test_spain_nie_valid() {
        assert!(validate_spain_id("X1234567L")); // Valid NIE with X
        assert!(validate_spain_id("Y1234567X")); // Valid NIE with Y
        assert!(validate_spain_id("Z1234567R")); // Valid NIE with Z
    }

    #[test]
    fn test_spain_invalid_check_letter() {
        assert!(!validate_spain_id("12345678A")); // Wrong letter for DNI
        assert!(!validate_spain_id("X1234567A")); // Wrong letter for NIE
    }

    #[test]
    fn test_spain_wrong_format() {
        assert!(!validate_spain_id("1234567Z")); // Too short
        assert!(!validate_spain_id("W1234567L")); // Invalid prefix (not X/Y/Z)
    }

    // ===== Belgian RRN Tests =====

    #[test]
    fn test_belgian_rrn_valid() {
        assert!(validate_belgian_rrn("85073000160")); // Valid pre-2000
        assert!(validate_belgian_rrn("85.07.30-001-60")); // With separators
    }

    #[test]
    fn test_belgian_rrn_post_2000() {
        // Post-2000 births use "2" prefix for calculation
        assert!(validate_belgian_rrn("00125000167")); // Valid post-2000 (2000-01-25)
    }

    #[test]
    fn test_belgian_rrn_invalid() {
        assert!(!validate_belgian_rrn("85073000184")); // Wrong check digits
        assert!(!validate_belgian_rrn("12345678901")); // Invalid checksum
    }

    #[test]
    fn test_belgian_rrn_wrong_length() {
        assert!(!validate_belgian_rrn("8507300016")); // Too short
        assert!(!validate_belgian_rrn("850730001600")); // Too long
    }

    // ===== German Steuer-ID Tests =====

    #[test]
    fn test_steuer_id_valid() {
        assert!(validate_steuer_id("86095742719")); // Valid Steuer-ID
        assert!(validate_steuer_id("47036892816")); // Valid Steuer-ID
        assert!(validate_steuer_id("65929970489")); // Valid Steuer-ID
    }

    #[test]
    fn test_steuer_id_with_spaces() {
        assert!(validate_steuer_id("860 957 427 19")); // With spaces
        assert!(validate_steuer_id("470-368-928-16")); // With dashes
    }

    #[test]
    fn test_steuer_id_invalid_checksum() {
        assert!(!validate_steuer_id("86095742710")); // Wrong check digit
        assert!(!validate_steuer_id("47036892817")); // Wrong check digit
    }

    #[test]
    fn test_steuer_id_all_same_digits() {
        assert!(!validate_steuer_id("11111111111")); // All same digits (not allowed)
        assert!(!validate_steuer_id("99999999999")); // All same digits
    }

    #[test]
    fn test_steuer_id_no_repeated_digit() {
        assert!(!validate_steuer_id("12345678901")); // No digit repeated 2-3 times
    }

    #[test]
    fn test_steuer_id_digit_repeated_four_times() {
        assert!(!validate_steuer_id("11115678901")); // Digit repeated 4 times (not allowed)
    }

    #[test]
    fn test_steuer_id_wrong_length() {
        assert!(!validate_steuer_id("8609574271")); // Too short (10 digits)
        assert!(!validate_steuer_id("860957427190")); // Too long (12 digits)
        assert!(!validate_steuer_id("")); // Empty
    }

    // ===== Portugal NIF Tests =====

    #[test]
    fn test_nif_valid() {
        // Valid Portuguese NIFs (mathematically correct)
        assert!(validate_portugal_nif("123456789"));
        assert!(validate_portugal_nif("234567899"));
        assert!(validate_portugal_nif("503442267"));
    }

    #[test]
    fn test_nif_valid_with_spaces() {
        assert!(validate_portugal_nif("123 456 789"));
        assert!(validate_portugal_nif("234 567 899"));
    }

    #[test]
    fn test_nif_invalid_checksum() {
        assert!(!validate_portugal_nif("123456780")); // Wrong check digit
        assert!(!validate_portugal_nif("234567891")); // Wrong check digit
    }

    #[test]
    fn test_nif_invalid_first_digit() {
        assert!(!validate_portugal_nif("423456789")); // Invalid first digit (4)
        assert!(!validate_portugal_nif("723456789")); // Invalid first digit (7)
        assert!(!validate_portugal_nif("823456789")); // Invalid first digit (8)
    }

    #[test]
    fn test_nif_wrong_length() {
        assert!(!validate_portugal_nif("12345678")); // Too short (8 digits)
        assert!(!validate_portugal_nif("1234567890")); // Too long (10 digits)
        assert!(!validate_portugal_nif("")); // Empty
    }

    #[test]
    fn test_nif_non_numeric() {
        assert!(!validate_portugal_nif("abcdefghi"));
        assert!(!validate_portugal_nif("12345678X"));
    }
}
