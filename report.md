# Promotion validation report

## Command

```sh
moon test --target all
```

## Relevant output

```text
Failed to run the test: _build/wasm/debug/test/rsa/rsa.blackbox_test.wasm
The test executable exited with signal: 15 (SIGTERM)
```

The command was run under a 180 second local timeout and did not complete before
the timeout terminated the wasm test executable.

## Analysis

The check command passed after the promotion fix. The remaining test issue is a
long-running or hanging wasm test in the RSA package under local execution; it
requires separate test-runtime investigation beyond the API deprecation update.
