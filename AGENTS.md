# Relay agent guide

Relay is developed independently from cluster deployment repositories.

- Keep one immutable provider per mount. Compile adapter capabilities into code.
- Never retrieve real credentials or perform real user/vendor onboarding.
- Do not print or persist credentials outside intended OpenBao barrier storage.
  Do not add raw HTTP logging, environment dumps, or upstream error reflection.
- Generate disposable test values in memory and suppress them in diagnostics.
- Require authenticated entity IDs; do not accept caller-selected user paths.
- Preserve durable records before external side effects and make cleanup
  idempotent, including ambiguous creation responses.
- Do not describe remote TTL or revocation guarantees beyond tested capabilities.
- The GitHub UAT candidate is experimental and absent from the production
  registry. Its human-only verifier does not establish request-ID recovery,
  native 15-minute expiry, or production readiness. Keep this boundary explicit.
- Do not run the GitHub verifier with real credentials or run real OAuth
  onboarding. Use generated in-memory fixtures for agent-operated tests.
- Run `make check` and `make build` before committing.
- Behavior-changing commits include concise `Why` and `How` body sections.
