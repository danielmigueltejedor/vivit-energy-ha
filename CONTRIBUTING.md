# Contributing to Vivit Energy Portal

Bug reports, provider-response samples, translations, documentation improvements and code contributions are welcome.

## Before opening an issue

1. Test the latest release and confirm the official customer portal is working.
2. Search existing issues for the same symptom.
3. Use the matching issue form and include exact Home Assistant and integration versions.
4. Remove usernames, passwords, cookies, signatures, contract/CUPS identifiers, addresses and invoice details.

Use Discussions for setup questions that are not reproducible integration defects.

## Code contributions

- Keep all network I/O asynchronous and use the Home Assistant-managed session.
- Treat the provider API as unstable: validate response shapes and preserve partial availability.
- Never log credentials, authentication tokens or customer identifiers.
- Avoid extra login attempts; Gigya can rate-limit or temporarily block repeated authentication.
- Preserve entity `unique_id` values and config-entry data unless a migration is included.
- Add regression tests for pure parsing and normalization logic.

Run the local checks before opening a pull request:

```bash
python -m pip install ruff
ruff check custom_components/repsol_vivit tests
python -m unittest discover -s tests -v
python -m compileall -q custom_components/repsol_vivit
```

Pull requests should explain the user-visible behavior, the validation performed and any compatibility or privacy impact.
