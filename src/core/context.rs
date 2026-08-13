/// Context analysis for GDPR special category detection
use crate::core::types::{ContextInfo, SpecialCategory};
use once_cell::sync::Lazy;
use regex::Regex;

static SNIPPET_SENSITIVE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap(),
        Regex::new(r"\b(?:\d[ -]?){4,}\d\b").unwrap(),
        Regex::new(r"\b[A-Za-z0-9_+/=-]{20,}\b").unwrap(),
    ]
});

/// Context analyzer that detects GDPR special category data
/// by examining keywords around PII matches
pub struct ContextAnalyzer {
    window_size: usize,
    medical_keywords: Vec<String>,
    biometric_keywords: Vec<String>,
    genetic_keywords: Vec<String>,
    criminal_keywords: Vec<String>,
}

impl ContextAnalyzer {
    pub fn new() -> Self {
        Self {
            window_size: 50, // characters before/after match
            medical_keywords: MEDICAL_KEYWORDS_ALL.iter().map(|s| s.to_string()).collect(),
            biometric_keywords: BIOMETRIC_KEYWORDS.iter().map(|s| s.to_string()).collect(),
            genetic_keywords: GENETIC_KEYWORDS.iter().map(|s| s.to_string()).collect(),
            criminal_keywords: CRIMINAL_KEYWORDS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Analyze context around a match position
    pub fn analyze(&self, text: &str, match_start: usize, match_end: usize) -> Option<ContextInfo> {
        self.analyze_internal(text, match_start, match_end, None)
    }

    /// Analyze context and include a best-effort redacted evidence snippet.
    ///
    /// `redaction_spans` contains byte spans for every recognized finding in
    /// the source. Additional email, numeric-identifier, and secret-like token
    /// patterns are masked defensively. Callers must opt into this method;
    /// normal context analysis never retains source text.
    pub fn analyze_with_redactions(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        redaction_spans: &[(usize, usize)],
    ) -> Option<ContextInfo> {
        self.analyze_internal(text, match_start, match_end, Some(redaction_spans))
    }

    fn analyze_internal(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        redaction_spans: Option<&[(usize, usize)]>,
    ) -> Option<ContextInfo> {
        if match_start > match_end || match_end > text.len() {
            return None;
        }

        // Detector offsets are bytes, while the privacy/context window is
        // defined in characters. Snap malformed offsets to UTF-8 boundaries
        // and walk characters so multilingual input cannot panic.
        let match_start = floor_char_boundary(text, match_start);
        let match_end = ceil_char_boundary(text, match_end);
        let before_start = if self.window_size == 0 {
            match_start
        } else {
            text[..match_start]
                .char_indices()
                .rev()
                .nth(self.window_size - 1)
                .map_or(0, |(index, _)| index)
        };
        let after_end = if self.window_size == 0 {
            match_end
        } else {
            text[match_end..]
                .char_indices()
                .nth(self.window_size)
                .map_or(text.len(), |(index, _)| match_end + index)
        };

        let context_window = format!(
            "{}{}",
            &text[before_start..match_start],
            &text[match_end..after_end]
        );

        // Detect keywords (case-insensitive)
        let context_lower = context_window.to_lowercase();
        let mut detected_keywords = Vec::new();
        let mut category = None;

        // Check medical keywords
        for keyword in &self.medical_keywords {
            if context_lower.contains(&keyword.to_lowercase()) {
                detected_keywords.push(keyword.clone());
                category = Some(SpecialCategory::Medical);
            }
        }

        // Check biometric keywords
        for keyword in &self.biometric_keywords {
            if context_lower.contains(&keyword.to_lowercase()) {
                detected_keywords.push(keyword.clone());
                category = Some(SpecialCategory::Biometric);
            }
        }

        // Check genetic keywords
        for keyword in &self.genetic_keywords {
            if context_lower.contains(&keyword.to_lowercase()) {
                detected_keywords.push(keyword.clone());
                category = Some(SpecialCategory::Genetic);
            }
        }

        // Check criminal keywords
        for keyword in &self.criminal_keywords {
            if context_lower.contains(&keyword.to_lowercase()) {
                detected_keywords.push(keyword.clone());
                category = Some(SpecialCategory::Criminal);
            }
        }

        // Without snippet opt-in, retain the historical behavior of returning
        // context only when classification signals were found.
        if detected_keywords.is_empty() && redaction_spans.is_none() {
            None
        } else {
            let redacted_snippet = redaction_spans.map(|spans| {
                redact_window(text, before_start, after_end, match_start, match_end, spans)
            });
            Some(ContextInfo {
                // Context text is deliberately not retained. It may contain
                // unrelated credentials or personal data adjacent to a match.
                #[allow(deprecated)]
                before: String::new(),
                #[allow(deprecated)]
                after: String::new(),
                redacted_snippet,
                keywords: detected_keywords,
                category,
            })
        }
    }
}

fn redact_window(
    text: &str,
    window_start: usize,
    window_end: usize,
    match_start: usize,
    match_end: usize,
    recognized_spans: &[(usize, usize)],
) -> String {
    let window = &text[window_start..window_end];
    let mut ranges = Vec::new();
    ranges.push((match_start, match_end));
    ranges.extend_from_slice(recognized_spans);
    for pattern in SNIPPET_SENSITIVE_PATTERNS.iter() {
        ranges.extend(
            pattern
                .find_iter(window)
                .map(|matched| (window_start + matched.start(), window_start + matched.end())),
        );
    }

    let mut ranges: Vec<(usize, usize)> = ranges
        .into_iter()
        .filter_map(|(start, end)| {
            let start = floor_char_boundary(text, start.max(window_start).min(window_end));
            let end = ceil_char_boundary(text, end.max(start).min(window_end));
            (start < end).then_some((start, end))
        })
        .collect();
    ranges.sort_unstable();

    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut redacted = String::with_capacity(window.len());
    let mut cursor = window_start;
    for (start, end) in merged {
        redacted.push_str(&text[cursor..start]);
        redacted.push_str("[REDACTED]");
        cursor = end;
    }
    redacted.push_str(&text[cursor..window_end]);
    redacted
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

impl Default for ContextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ===== Multi-lingual Keyword Lists =====

/// Medical keywords (English + Latin + Dutch + German + French)
pub const MEDICAL_KEYWORDS_ALL: &[&str] = &[
    // English - General
    "patient",
    "patients",
    "medical",
    "hospital",
    "clinic",
    "doctor",
    "physician",
    "nurse",
    "healthcare",
    "health care",
    "diagnosis",
    "treatment",
    "therapy",
    "prescription",
    "medication",
    "medicine",
    "surgery",
    "operation",
    "procedure",
    "practitioner",
    "gp",
    "specialist",
    "consultant",
    // English - Sensitive conditions (GDPR Art. 9)
    "hiv",
    "aids",
    "cancer",
    "oncology",
    "diabetes",
    "psychiatric",
    "mental health",
    "psychology",
    "psychotherapy",
    "depression",
    "anxiety",
    "addiction",
    "substance abuse",
    "abortion",
    "fertility",
    "ivf",
    "genetic disorder",
    "hereditary",
    "dna test",
    // English - Medical facilities
    "ward",
    "emergency",
    "icu",
    "intensive care",
    "surgery",
    "radiology",
    // Dutch
    "patiënt",
    "patiënte",
    "patiënten",
    "medisch",
    "medische",
    "ziekenhuis",
    "kliniek",
    "arts",
    "dokter",
    "huisarts",
    "verpleegkundige",
    "verpleging",
    "zorg",
    "gezondheidszorg",
    "diagnose",
    "behandeling",
    "therapie",
    "recept",
    "medicatie",
    "medicijn",
    "operatie",
    "ingreep",
    "zorgverlener",
    "zorginstelling",
    "ggz",
    "thuiszorg",
    // German
    "patient",
    "patientin",
    "patienten",
    "medizinisch",
    "medizinische",
    "krankenhaus",
    "klinik",
    "arzt",
    "ärztin",
    "krankenschwester",
    "gesundheit",
    "diagnose",
    "behandlung",
    "therapie",
    "rezept",
    "medikament",
    "operation",
    "eingriff",
    "krankenversicherung",
    // French
    "patient",
    "patiente",
    "médical",
    "médicale",
    "hôpital",
    "clinique",
    "médecin",
    "docteur",
    "infirmière",
    "santé",
    "diagnostic",
    "traitement",
    "thérapie",
    "ordonnance",
    "médicament",
    "opération",
    "chirurgie",
    // Latin/Medical terminology (universal)
    "anamnesis",
    "prognosis",
    "symptom",
    "syndrome",
    "pathology",
];

/// Biometric keywords
pub const BIOMETRIC_KEYWORDS: &[&str] = &[
    "fingerprint",
    "fingerprints",
    "biometric",
    "biometrics",
    "facial recognition",
    "face recognition",
    "iris scan",
    "retina scan",
    "dna",
    "genetic",
    "voiceprint",
    "voice recognition",
    "palm print",
    "handwriting",
    // Dutch
    "vingerafdruk",
    "vingerafdrukken",
    "biometrisch",
    "biometrische",
    "gezichtsherkenning",
    "irisscan",
    "retinascan",
    // German
    "fingerabdruck",
    "biometrisch",
    "gesichtserkennung",
    "iriserkennung",
    // French
    "empreinte digitale",
    "biométrique",
    "reconnaissance faciale",
];

/// Genetic keywords
pub const GENETIC_KEYWORDS: &[&str] = &[
    "genetic",
    "genetics",
    "genome",
    "genomic",
    "dna",
    "rna",
    "gene",
    "genes",
    "chromosome",
    "hereditary",
    "inherited",
    "genetic test",
    "genetic screening",
    "genetic disorder",
    // Dutch
    "genetisch",
    "genetische",
    "genoom",
    "gen",
    "genen",
    "chromosoom",
    "erfelijk",
    "erfelijke",
    "genetische test",
    // German
    "genetisch",
    "genom",
    "gen",
    "chromosom",
    "erblich",
    // French
    "génétique",
    "génome",
    "gène",
    "chromosome",
    "héréditaire",
];

/// Criminal/Legal keywords
pub const CRIMINAL_KEYWORDS: &[&str] = &[
    "conviction",
    "convictions",
    "criminal",
    "arrest",
    "arrested",
    "police",
    "court",
    "lawsuit",
    "prosecution",
    "prosecutor",
    "offense",
    "offence",
    "crime",
    "crimes",
    "sentence",
    "sentenced",
    "probation",
    "parole",
    "detention",
    "prison",
    "jail",
    "inmate",
    "felon",
    "felony",
    // Dutch
    "veroordeling",
    "veroordeeld",
    "crimineel",
    "arrestatie",
    "politie",
    "rechtbank",
    "vervolging",
    "strafbaar",
    "misdaad",
    "gevangenis",
    "celstraf",
    "voorwaardelijk",
    "reclassering",
    // German
    "verurteilung",
    "verurteilt",
    "kriminell",
    "verhaftung",
    "polizei",
    "gericht",
    "straftat",
    "verbrechen",
    "gefängnis",
    "haft",
    // French
    "condamnation",
    "condamné",
    "criminel",
    "arrestation",
    "police",
    "tribunal",
    "poursuite",
    "infraction",
    "crime",
    "prison",
];

/// Financial keywords (for severity upgrade)
pub const FINANCIAL_KEYWORDS: &[&str] = &[
    "account",
    "bank account",
    "payment",
    "transaction",
    "transfer",
    "salary",
    "income",
    "wage",
    "loan",
    "credit",
    "debit",
    "balance",
    "invoice",
    "billing",
    "mortgage",
    "pension",
    // Dutch
    "rekening",
    "bankrekening",
    "betaling",
    "transactie",
    "overboeking",
    "salaris",
    "inkomen",
    "loon",
    "lening",
    "hypotheek",
    "pensioen",
    // German
    "konto",
    "bankkonto",
    "zahlung",
    "transaktion",
    "überweisung",
    "gehalt",
    "einkommen",
    "darlehen",
    "hypothek",
    "rente",
    // French
    "compte",
    "compte bancaire",
    "paiement",
    "transaction",
    "virement",
    "salaire",
    "revenu",
    "prêt",
    "hypothèque",
    "pension",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_medical_context_detection() {
        let analyzer = ContextAnalyzer::new();
        let text = "Patient John Doe with BSN 123456782 diagnosed with diabetes.";
        let match_start = 26; // Start of "123456782"
        let match_end = 35; // End of "123456782"

        let context = analyzer.analyze(text, match_start, match_end);
        assert!(context.is_some());

        let ctx = context.unwrap();
        assert!(ctx.keywords.contains(&"patient".to_string()));
        // "diagnosed" contains "diagnose" substring
        assert!(ctx.keywords.iter().any(|k| k.contains("diagnos")));
        assert_eq!(ctx.category, Some(SpecialCategory::Medical));
    }

    #[test]
    fn test_no_context_detection() {
        let analyzer = ContextAnalyzer::new();
        let text = "Customer ID: 123456782 for order processing.";
        let match_start = 13;
        let match_end = 22;

        let context = analyzer.analyze(text, match_start, match_end);
        assert!(context.is_none());
    }

    #[test]
    fn test_biometric_context() {
        let analyzer = ContextAnalyzer::new();
        let text = "Fingerprint record for ID 123456782 stored in system.";
        let match_start = 26;
        let match_end = 35;

        let context = analyzer.analyze(text, match_start, match_end);
        assert!(context.is_some());

        let ctx = context.unwrap();
        assert!(ctx.keywords.iter().any(|k| k.contains("fingerprint")));
        assert_eq!(ctx.category, Some(SpecialCategory::Biometric));
    }

    #[test]
    fn unicode_window_does_not_slice_inside_a_character() {
        let analyzer = ContextAnalyzer::new();
        let text = format!("{}patient {}", "é".repeat(80), "123456782");
        let match_start = text.find("123456782").unwrap();

        let context = analyzer
            .analyze(&text, match_start, match_start + 9)
            .expect("medical context should be found");
        assert_eq!(context.category, Some(SpecialCategory::Medical));
        #[allow(deprecated)]
        {
            assert!(context.before.is_empty());
            assert!(context.after.is_empty());
        }
    }

    #[test]
    fn malformed_offsets_are_handled_without_panicking() {
        let analyzer = ContextAnalyzer::new();
        let text = "patient é 123456782";
        // Offset 9 is inside the two-byte 'é'.
        assert!(analyzer.analyze(text, 9, text.len()).is_some());
        assert!(analyzer
            .analyze(text, text.len() + 1, text.len() + 1)
            .is_none());
    }

    #[test]
    fn redacted_snippet_masks_current_and_adjacent_findings() {
        let analyzer = ContextAnalyzer::new();
        let text = "patient 111222333 email other@example.com diagnosis";
        let bsn_start = text.find("111222333").unwrap();
        let email_start = text.find("other@example.com").unwrap();
        let spans = vec![
            (bsn_start, bsn_start + 9),
            (email_start, email_start + "other@example.com".len()),
        ];

        let context = analyzer
            .analyze_with_redactions(text, bsn_start, bsn_start + 9, &spans)
            .unwrap();
        let snippet = context.redacted_snippet.unwrap();
        assert_eq!(snippet.matches("[REDACTED]").count(), 2);
        assert!(!snippet.contains("111222333"));
        assert!(!snippet.contains("other@example.com"));
    }
}
