# Repository Guidelines

firma-sri signs the SRI's electronic documents (comprobantes electrónicos) with a .p12 certificate, as XAdES-BES, and verifies their signatures. It is a small TypeScript library, published to npm as an ES module for Node.js 22 or later. The README and the CHANGELOG are in Spanish, for its users; code identifiers, error messages and these guidelines are in English.

## The signature

The signer is written from the specifications alone, never from another implementation: the SRI's ficha técnica (section 6.8), XMLDSig, XAdES 1.3.2 (ETSI TS 101 903), Canonical XML 1.0 and RFC 4514. Every choice cites its section in a comment beside the code. The signer never rewrites the document: it appends the signature before the root's end tag and refuses a document it can't sign that way, with a reason.

A change to what the signature contains is checked against the SRI's test environment (Pruebas) for all six document types before it is released.

## Dependencies

The runtime dependencies parse XML, check signatures and open PKCS#12 files, so they are caret ranges: whoever installs the library gets their security patches without waiting for a release here. `pnpm audit --prod` reports nothing before a release. Development dependencies are pinned exactly.

## Checks

`pnpm check` (format, lint and unused code), `pnpm check-types`, `pnpm test`, `pnpm build` and `pnpm check-package` (publint and attw) pass before every commit. CI runs all of them on every push. `pnpm fix` writes the formatting and the safe fixes. Never disable a lint rule to pass it.

## Tests

Tautological tests are harmful. For each test, name a production change that would make it fail; otherwise delete it. Assert observable behavior against independent expectations, never an echo of a fixture, mock response or the production arithmetic itself.

Prefer property-based tests, with [Hegel](https://hegel.dev/), over the random documents `tests/documents.ts` draws. A signature is checked by something other than the signer: xml-crypto, xmlsec1 (CI installs it; locally its tests run when it is installed), `node:crypto` reading the certificate, and the SRI's, the W3C's and the ETSI's schemas in `tests/data/xsd`. Keep example-based tests for fixed contracts and known regressions. A fixed figure in an assertion cites where it comes from, in the test's title or a comment beside it; `pnpm check` refuses an uncited one (`honest-tests/literal-needs-source`), along with snapshots and mock call counts. Never cite a source the value doesn't come from to get past it.

## Comments

A comment sits on the code it explains: never a file header, never above or among the imports (`file-comments/no-head-comments`).

## Changes

Every change reaches `main` through a pull request, merged with a squash once CI passes; `main` is protected and nobody pushes to it directly. A commit message is a short plain subject that says what changed, with no body.

## Releases

Bump `version` in `package.json` and add its entry to `CHANGELOG.md`, then push a `vX.Y.Z` tag that matches. `.github/workflows/publish.yml` publishes it with npm's trusted publishing and a provenance statement; no token is stored anywhere. A breaking change to what any function accepts, or to what a signature contains, is a major version.
