These lockfiles intentionally pin old, vulnerable versions so the tests can check detection.
They are named `*.fixture.json` (not `package-lock.json`) so GitHub's dependency graph and
Dependabot don't report them as real dependencies of this repo. Use `copyFixture()` from
`test/helpers.ts` to materialize one as a real project in a temp folder.
