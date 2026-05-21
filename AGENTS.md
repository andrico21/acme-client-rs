# Project conventions for AI agents

## Git tags
- **Tag format: bare semver, NO `v` prefix.** Example: `2.1.0`, not `v2.1.0`.
- Existing `v*` tags are legacy; new tags MUST omit the prefix.
- Always use annotated tags (`git tag -a <version> -m "..."`).

## Release flow
- Bump `Cargo.toml` version first, commit, push, then tag.
- Push tags explicitly: `git push origin <version>`.
