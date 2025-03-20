## v1.2.3 (Released 2025-03-20)

IMPROVEMENTS

- fix: verify type casting

BUILD

- chore(deps): update dependency go to v1.24.1 (#72)
- fix(deps): update module github.com/beevik/etree to v1.5.0 (#68)

## v1.2.2 (Released 2024-06-10)

IMPROVEMENTS

- fix: allow no Transforms when signing
- fix: removed XML declaration before signature operations
- examples: run 3.6 in tests

BUILD

- fix(deps): update module github.com/beevik/etree to v1.4.0

## v1.2.1 (Released 2024-03-20)

IMPROVEMENTS

- fix: handle adjacent comments during canonicalization
- feat: support http://www.w3.org/TR/2001/REC-xml-c14n-20010315

## v1.2.0 (Released 2024-02-19)

ADDITIONS

- signer: add convenience method for creating a signer given an already built etree.Document

IMPROVEMENTS

- fix: support Signature element on the root level

BUILD

- build: use latest stable Go release
- fix(deps): update module github.com/beevik/etree to v1.3.0
- fix(deps): update module github.com/smartystreets/goconvey to v1.8.1

## v1.1.1 (Released 2023-06-08)

IMPROVEMENTS

- Preserve CDATA text when signing a document
- Typo in TestEnvelopedSignatureProcess

## v1.1.0 (Released 2023-05-30)

IMPROVEMENTS

- feat: replace Validate() with ValidateReferences()
- meta: use moov-io/infra Go linter script in CI

## v1.0.0 (Released 2023-04-21)

This is the first tagged release of the `moov-io/signedxml` package. It was previously released `ma314smith/signedxml` but has been moved over to the Moov.io Github organization.
