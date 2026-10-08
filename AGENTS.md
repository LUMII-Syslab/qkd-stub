# Documentation and wiki maintenance

When changing documented behavior, update the README, relevant `docs/` files,
and affected GitHub wiki pages in the same task. This includes key-ID formats,
derivation formulas and labels, API behavior, authorization, CLI options,
deployment, and testing instructions.

The wiki is a separate Git repository:
`https://github.com/LUMII-Syslab/qkd-stub.wiki.git`.
Fetch its latest state before editing; commit and push the relevant wiki updates
when publishing is authorized. If access or authorization prevents publication,
report the pending wiki changes explicitly rather than claiming it is up to date.

For key derivation, check `src/keys.rs`, `docs/encrypted-key-ids.md`, and the wiki's
`Key-ID-and-Key-Derivation.md` together. Keep formulas, byte layouts, format
versions, limits, migration notes, and test vectors consistent. Update or remove
obsolete diagrams and check related wiki pages for stale descriptions.
