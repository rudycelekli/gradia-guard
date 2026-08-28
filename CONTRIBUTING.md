# Contributing

Gradia Guard accepts focused issues and pull requests that preserve its central
invariant: evidence may narrow a claim, but product copy, payment, or reviewer
opinion may never expand observed coverage.

## Before opening a pull request

1. Discuss material schema or assurance changes in an issue.
2. Add a negative test for every new refusal or claim boundary.
3. Run `npm ci` and `npm run prepack`.
4. Run `npm run release:verify` from an exact clean commit before requesting a
   release; local iteration may use `npm run release:verify:dev`, whose receipt
   is explicitly not publishable.
5. Do not add credentials, customer data, raw provider traces, or private
   benchmark artifacts.

Contributions intentionally submitted for inclusion are licensed under
Apache-2.0 as described by `LICENSE`. The Gradia name and marks are not granted
for derivative branding.
