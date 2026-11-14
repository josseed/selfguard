## What and why

<!-- What does this change, and why is it needed? Link the issue if there is one. -->

## Checklist

- [ ] `npm run typecheck && npm test` pass
- [ ] Tests cover the change (bug fixes include a test that fails without the fix)
- [ ] No runtime dependencies added; nothing from scanned projects is executed
- [ ] Untrusted text that is printed, notified or returned to an AI goes through `clean()`
- [ ] Docs (`docs/`, `src/guide.ts`) and `CHANGELOG.md` updated if behavior changed
