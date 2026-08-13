# Built-in detectors

PII Radar 0.6 registers the following built-in detectors by default.

| Detector ID | Scope | Candidate type |
| --- | --- | --- |
| `be_rrn` | Belgium | National Register number |
| `danish_cpr` | Denmark | CPR number |
| `finnish_hetu` | Finland | Personal identity code |
| `fr_nir` | France | NIR |
| `de_steuer_id` | Germany | Tax identification number |
| `it_codice_fiscale` | Italy | Codice Fiscale |
| `nl_bsn` | Netherlands | BSN |
| `norwegian_fodselsnummer` | Norway | Fødselsnummer |
| `polish_pesel` | Poland | PESEL |
| `pt_nif` | Portugal | NIF |
| `es_dni` | Spain | DNI |
| `es_nie` | Spain | NIE |
| `swedish_personnummer` | Sweden | Personnummer |
| `gb_nhs` | United Kingdom | NHS number |
| `iban` | International | IBAN |
| `creditcard` | Universal | Payment-card number |
| `email` | Universal | Email address |
| `api_key` | Universal | API keys, tokens, JWTs, private-key markers, and high-entropy secret candidates |

Run `pii-radar detectors --verbose` to inspect the detector set in the installed build.

## Filtering

`--countries` accepts comma-separated lowercase codes. It limits jurisdiction-specific detectors while retaining universal detectors:

```console
pii-radar scan ./data --countries dk,fi,no,se
```

`--min-confidence low|medium|high` sets the reporting threshold. Confidence reflects the evidence available to a detector; it is not a measured probability that the value belongs to a person.

## Validation and context

Depending on the format, a detector can combine a bounded pattern with length, structure, checksum, date, or control-character validation. Context analysis can use nearby terms to classify a match; it does not rewrite the detector's evidence-based severity. Neither mechanism establishes that a value is assigned, current, personal in the relevant context, or subject to a particular law.

False positives can arise from test data, reference numbers, random digit sequences, and token-like strings. False negatives can arise from alternate formatting, OCR errors, encoding, unsupported documents, truncated responses, sampling, obfuscation, or new credential formats. Evaluate detector behaviour against representative synthetic fixtures and review important findings manually.

Use a [schema-versioned plugin](plugins.md) for a domain-specific identifier that is not built in.
