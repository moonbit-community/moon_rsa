# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

moon_rsa is a MoonBit implementation of the RSA cryptographic algorithm. It is currently under development and is intended as an **educational reference implementation** that is not professionally certified or reviewed for production security use.

Key dependencies:
- MoonBit language
- `moonbitlang/x/crypto` for cryptographic operations
- `moonbitlang/x` v0.4.38 for utilities

## Common Development Commands

### Building and Checking
- `moon check --target all` - Lint check and type checking across all targets
- `moon info` - Generate/update package interface files (`.mbti`). Run after structural changes to inspect the diff for breaking changes
- `moon fmt` - Format code to match MoonBit style conventions

### Testing
- `moon test --target all` - Run all tests (blackbox and whitebox)
- `moon test --update` - Update snapshot tests when behavior intentionally changes
- `moon coverage analyze > uncovered.log` - Analyze code coverage and identify untested sections

### Development Workflow
The typical workflow before committing:
```bash
moon test --target all   # Verify all tests pass
moon fmt                 # Format code
moon info                # Update package interfaces
git diff                 # Verify only expected changes
```

## Code Architecture

### Project Structure
- **Root level** (`moon.mod.json`) - Module metadata and version
- **`rsa/` package** - The main RSA implementation
  - `types.mbt` - Core type definitions for RSA keys (RsaPublicKey, RsaPrivateKey, etc.)
  - `rsa.mbt` - RSA algorithm implementation including key generation, signing, encryption
  - `rsa_test.mbt` - Blackbox tests for RSA functionality

### Key Implementation Areas

#### RSA Key Types (`rsa/types.mbt`)
Defines RFC 8017 PICS #1 v2.2 compliant structures:
- **RsaPublicKey** - Contains modulus and public exponent
- **RsaPrivateKey** - Contains full private key material (modulus, exponents, CRT parameters)
- **RsaVersion** - Enum for TWO_PRIME and MULTI (for multi-prime RSA)
- **OtherPrimeInfo** - Additional prime factors for multi-prime RSA

#### RSA Algorithm (`rsa/rsa.mbt`)
Key functions:
- `generate_probably_primes(nlen, e)` - Generates probable primes p and q per FIPS 186-5 A.1.3
- RSA signature operations with RSASSA-PSS
- RSA encryption/decryption with RSAES-OAEP
- Helper functions: `gcd()`, `get_random_32_bytes_seed()`, `abs()`

### Current Features
- ✅ RSA key pair generation (2048-bit minimum)
- ✅ RSASSA-PSS signature generation & verification
- ✅ RSAES-OAEP encryption/decryption

### Planned Features
- RSAES-PKCS1-v1_5 signature and encryption schemes
- Full FIPS 186.5 compliance

## MoonBit Coding Conventions

### Block Organization
Code is organized into blocks separated by `///|` markers. Block order is irrelevant and can be processed independently during refactoring.

### Code Organization Patterns
- Deprecated code should be kept in `deprecated.mbt` files within each package
- Use `inspect` for debugging output in tests and run `moon test --update` to snapshot the output
- Use `assert_eq` primarily in loops where snapshot output may vary per iteration
- Suppress compiler warnings for intentionally unused types/variants by creating a `_suppress_unused_warnings()` function that references them

### Testing Philosophy
- Prefer snapshot testing with `inspect` over manual assertions
- Update snapshots when behavior intentionally changes with `moon test --update`
- Check code coverage regularly to identify untested paths

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/check.yml`):
- Runs on: ubuntu-latest, macos-latest, windows-latest
- Triggers: pull requests and pushes to master
- Steps:
  1. Install MoonBit CLI
  2. Run `moon check --target all`
  3. Run `moon test --target all`
  4. Format check with `moon fmt` (fails if formatting is needed)
  5. Interface check with `moon info` (fails if interfaces change unexpectedly)

The workflow ensures all changes are properly formatted, type-checked, and tested before merging.

## Standards and Compliance

The implementation follows:
- **RFC 8017** - PKCS #1: RSA Cryptography Specifications v2.2
- **FIPS 186-5** - Digital Signature Standard (especially A.1.3 for prime generation)

These standards are referenced in docstrings and comments throughout the code.
