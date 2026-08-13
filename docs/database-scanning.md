# Database scanning

Database scanning is included in the full release artifact. Source builds enable it with the `database` feature:

```console
cargo build --release --features database
```

Version 0.6 supports PostgreSQL and MongoDB. MySQL, MariaDB, and SQLite are not supported.

## Connect

Use credentials limited to read-only access on the intended database, tables, or collections. Pass the name of a protected environment variable through `--connection-env` rather than putting a literal connection string in shell history.

For an interactive invocation:

```console
export DATABASE_URL='postgresql://scanner@db.example.invalid/review'
pii-radar scan-db \
  --db-type postgres \
  --connection-env DATABASE_URL \
  --tables public.customers \
  --columns email,reference \
  --format json
```

MongoDB requires a database name:

```console
export MONGODB_URI='mongodb://scanner@db.example.invalid:27017'
pii-radar scan-db \
  --db-type mongodb \
  --connection-env MONGODB_URI \
  --database review \
  --tables customers \
  --row-limit 1000
```

`--connection-env` reads the value inside the process and keeps it out of the command arguments. Environment variables can still be exposed by privileged users, crash tooling, or process inspection; prefer a secret manager or protected environment on a trusted host.

## Restrict scope

Use `--tables` and `--columns` to opt into known targets. `--exclude-tables` and `--exclude-columns` remove targets from broader discovery. Names are comma-separated. In 0.6, PostgreSQL discovery is limited to base tables in the `public` schema; table filters may use `customers` or `public.customers`, and other schemas are not scanned. Sampling and row limits reduce load but also reduce coverage:

```console
pii-radar scan-db \
  --db-type postgres \
  --connection-env DATABASE_URL \
  --exclude-tables audit_log,sessions \
  --sample-percent 10 \
  --row-limit 5000 \
  --pool-size 2
```

A report from a sample describes only the rows returned by that sample. It cannot establish that unscanned rows contain no matching data.

For PostgreSQL, each selected value is rendered through PostgreSQL's `TEXT` representation before detection. This includes numeric, temporal, UUID, JSON, array, enum, and binary columns instead of treating non-text columns as empty. The scanner sees the database representation, not an application-level decoding: for example, `bytea` is normally rendered as hexadecimal text. Exclude custom or very large columns when their text output is not useful or would add unacceptable database load.

Database scans support the common `terminal`, `json`, `json-compact`, `csv`, and `html` output formats. Use `--output PATH` for a report file and `--force` only when replacing that exact file is intended.

## Operational safety

- Test filters against a non-production copy when possible.
- Use a read-only role and network policy that cannot modify data or access unrelated databases.
- Keep pool size and sampling conservative to avoid production load.
- Expect query names and timing to appear in database audit logs.
- Stop if table or collection discovery exposes a larger scope than authorised.
- Protect output files as you would protect the source database.

A connector, authentication, query, or decoding error aborts the command with exit code `3` and no report payload; findings accumulated before that error are not rendered. Finding-limit truncation is different: it emits a partial report and returns `3`. See [output formats](output-formats.md) and [security and privacy](security-and-privacy.md).
