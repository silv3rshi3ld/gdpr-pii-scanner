// Performance benchmarks for PII-Radar
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pii_radar::{default_registry, ScanEngine};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a temporary directory with test files
fn create_test_files(dir: &TempDir, count: usize, content: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for i in 0..count {
        let file_path = dir.path().join(format!("test_{}.txt", i));
        fs::write(&file_path, content).unwrap();
        paths.push(file_path);
    }
    paths
}

/// Benchmark: Plain text scanning (baseline)
fn bench_plain_text_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("plain_text_scanning");

    // Test with different file counts
    for size in [10, 100, 1000].iter() {
        let temp_dir = TempDir::new().unwrap();
        let content =
            "John Doe\nemail: john.doe@example.com\nIBAN: NL91ABNA0417164300\nBSN: 123456782\n";
        let _files = create_test_files(&temp_dir, *size, content);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_size| {
            let registry = default_registry();
            let engine = ScanEngine::new(registry).show_progress(false);

            b.iter(|| {
                let results = engine.scan_directory(black_box(temp_dir.path()));
                black_box(results);
            });
        });
    }

    group.finish();
}

/// Benchmark: Individual detector performance
fn bench_detector_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("detector_performance");

    let registry = default_registry();
    let test_text = "Contact: john.doe@example.com\nIBAN: NL91ABNA0417164300\nBSN: 123456782\nCredit Card: 4532-0151-1283-0366\nAPI Key: AKIAIOSFODNN7EXAMPLE\nJWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n";
    let path = PathBuf::from("bench.txt");

    // Benchmark a few key detectors
    for detector_id in ["email", "iban", "nl_bsn", "credit_card", "api_key"] {
        if let Some(detector) = registry.get(detector_id) {
            group.bench_with_input(
                BenchmarkId::new("detector", detector_id),
                &test_text,
                |b, text| {
                    b.iter(|| {
                        let matches = detector.detect(black_box(*text), black_box(&path));
                        black_box(matches);
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark: Text with varying PII density
fn bench_pii_density(c: &mut Criterion) {
    let mut group = c.benchmark_group("pii_density");

    let registry = default_registry();
    let engine = ScanEngine::new(registry).show_progress(false);

    // Low density: 1 PII per 1000 chars
    let low_density = format!(
        "{}email: test@example.com\n{}",
        "Normal text. ".repeat(50),
        "More normal text. ".repeat(50)
    );

    // Medium density: 1 PII per 100 chars
    let medium_density = format!(
        "{}email: test@example.com\n{}IBAN: NL91ABNA0417164300\n{}",
        "Normal text. ".repeat(5),
        "More text. ".repeat(5),
        "Even more text. ".repeat(5)
    );

    // High density: Multiple PII per line
    let high_density =
        "email: test@example.com IBAN: NL91ABNA0417164300 BSN: 123456782 Card: 4532015112830366\n"
            .repeat(10);

    let temp_dir = TempDir::new().unwrap();

    for (name, content) in [
        ("low", low_density),
        ("medium", medium_density),
        ("high", high_density),
    ]
    .iter()
    {
        let file_path = temp_dir.path().join(format!("{}_density.txt", name));
        fs::write(&file_path, content).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(name), name, |b, _| {
            b.iter(|| {
                let results = engine.scan_directory(black_box(temp_dir.path()));
                black_box(results);
            });
        });
    }

    group.finish();
}

/// Benchmark: Large single file vs many small files
fn bench_file_size_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_size_distribution");

    let registry = default_registry();
    let engine = ScanEngine::new(registry).show_progress(false);

    let content_line = "Normal text with email: user@example.com and some more text.\n";

    // One large file (10KB)
    let large_temp = TempDir::new().unwrap();
    let large_content = content_line.repeat(100);
    fs::write(large_temp.path().join("large.txt"), &large_content).unwrap();

    // Many small files (100 files × 100 bytes)
    let small_temp = TempDir::new().unwrap();
    let small_content = content_line.to_string();
    let _files = create_test_files(&small_temp, 100, &small_content);

    group.bench_function("one_large_file", |b| {
        b.iter(|| {
            let results = engine.scan_directory(black_box(large_temp.path()));
            black_box(results);
        });
    });

    group.bench_function("many_small_files", |b| {
        b.iter(|| {
            let results = engine.scan_directory(black_box(small_temp.path()));
            black_box(results);
        });
    });

    group.finish();
}

/// Benchmark: Pattern complexity
fn bench_pattern_complexity(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_complexity");

    // Create temp directories for each test
    let simple_dir = TempDir::new().unwrap();
    let complex_dir = TempDir::new().unwrap();
    let very_complex_dir = TempDir::new().unwrap();

    // Simple pattern (email)
    let simple_text = "contact@example.com ".repeat(100);
    fs::write(simple_dir.path().join("test.txt"), &simple_text).unwrap();

    // Complex pattern (IBAN with validation)
    let complex_text = "NL91ABNA0417164300 ".repeat(100);
    fs::write(complex_dir.path().join("test.txt"), &complex_text).unwrap();

    // Very complex (API keys with entropy calculation)
    let very_complex_text =
        "api_key=AKIAIOSFODNN7EXAMPLE secret=dGhpc2lzYXZlcnlsb25nYmFzZTY0ZW5jb2RlZHNlY3JldGtleQ== "
            .repeat(50);
    fs::write(very_complex_dir.path().join("test.txt"), &very_complex_text).unwrap();

    for (name, dir) in [
        ("simple_email", &simple_dir),
        ("complex_iban", &complex_dir),
        ("very_complex_api", &very_complex_dir),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(name), dir, |b, dir| {
            let registry = default_registry();
            let engine = ScanEngine::new(registry).show_progress(false);

            b.iter(|| {
                let results = engine.scan_directory(black_box(dir.path()));
                black_box(results);
            });
        });
    }

    group.finish();
}

/// Benchmark: Thread scaling
fn bench_thread_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("thread_scaling");

    let temp_dir = TempDir::new().unwrap();
    let content = "email: test@example.com\nIBAN: NL91ABNA0417164300\nBSN: 123456782\n";
    let _files = create_test_files(&temp_dir, 100, content);

    // Note: ScanEngine doesn't expose thread count configuration in constructor
    // It uses rayon's thread pool which is configured globally
    // This benchmark will just test default threading
    group.bench_function("default_threading", |b| {
        let registry = default_registry();
        let engine = ScanEngine::new(registry).show_progress(false);

        b.iter(|| {
            let results = engine.scan_directory(black_box(temp_dir.path()));
            black_box(results);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_plain_text_scanning,
    bench_detector_performance,
    bench_pii_density,
    bench_file_size_distribution,
    bench_pattern_complexity,
    bench_thread_scaling
);
criterion_main!(benches);
