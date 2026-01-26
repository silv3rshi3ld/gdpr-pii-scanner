/// Context analysis for GDPR special category detection
use crate::core::types::{ContextInfo, SpecialCategory};

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
        // Extract context window
        let before_start = match_start.saturating_sub(self.window_size);
        let after_end = (match_end + self.window_size).min(text.len());

        let before = &text[before_start..match_start];
        let after = &text[match_end..after_end];
        let context_window = format!("{}{}", before, after);

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

        // Only return context if keywords were found
        if detected_keywords.is_empty() {
            None
        } else {
            Some(ContextInfo {
                before: before.to_string(),
                after: after.to_string(),
                keywords: detected_keywords,
                category,
            })
        }
    }
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
}
