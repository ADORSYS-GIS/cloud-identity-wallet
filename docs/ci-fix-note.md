# CI Fix: aws-lc-sys Build Failure

## Issue
CI pipeline failed when building with `--all-features` due to missing build dependencies for `aws-lc-sys` and `aws-lc-fips-sys` crates.

## Root Cause
The `--all-features` flag enables internal TLS features in `reqwest` (`__rustls-aws-lc-rs`), which requires building `aws-lc-sys` and `aws-lc-fips-sys`. These crates need:
- **cmake** - build system
- **golang-go** - Go compiler for generating assembly files

## Fix
Added `cmake` and `golang-go` installation to all CI jobs using `--all-features` in `.github/workflows/ci.yml`.
