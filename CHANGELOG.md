## v1.4.2 (Released 2026-10-26)

IMPROVEMENTS

- fix: bound InclusiveNamespaces PrefixList during exclusive c14n (#156)
- fix: cap SignedInfo references and skip redundant document copies (#154)

## v1.4.1 (Released 2026-08-26)

IMPROVEMENTS

- fix: exclusive canonicalization now updates in-scope prefixes incrementally instead of copying the full prefix map at every node

BUILD

- security: enable weekly scanners and a Dependabot cooldown

## v1.4.0 (Released 2026-08-18)

ADDITIONS

- feat: add SetCryptoExtensions for Brainpool certificates and signatures (#125)
- feat: look up signature references by ID, Id, or id (#123)

## v1.3.1 (Released 2026-08-13)

ADDITIONS

- feat: introduce NewValidatorFromDoc

IMPROVEMENTS

- fix: don't panic on quoted Reference URIs

## v1.3.0 (Released 2026-04-02)

ADDITIONS

- feat: add the xmlenc package for XML Encryption 1.1
- feat: support RSA-PSS (RSASSA-PSS) signature algorithms
- feat: support Ed25519 (eddsa-ed25519) signatures
- fix: leverage the crypto.Signer interface

IMPROVEMENTS

- fix: verify ECDSA signatures in the raw r||s form used by XML DSig
- fix: pass InclusiveNamespaces from CanonicalizationMethod to ProcessElement
- fix: handle C14N for both inline and transformed references

## v1.2.5 (Released 2026-01-06)

IMPROVEMENTS

- chore: fix module name

## v1.2.4 (Released 2026-01-06)

IMPROVEMENTS

- fix: retain CDATA during signing
- fix: validation for XAdES signatures

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
