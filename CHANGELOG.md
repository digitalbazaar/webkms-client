# webkms-client ChangeLog

## 7.0.0 - 2021-07-22

### Changed
- **BREAKING**: All root zcaps use `urn:root:zcap:` prefix. Root zcaps
  for keys are the keystore root zcap where the controller resides, not
  the key. This new client version must be paired with a new WebKMS
  server, it is not compatible with an old version.
- **BREAKING**: `getKeystore` is now an instance member function instead
  of a static class member function. It requires that a capability be
  invoked to fetch the keystore config.
- **BREAKING**: The `keystore` parameter passed to `KmsClient` and
  `KeystoreAgent` constructors has been renamed to `keystoreId` to
  help avoid confusion (it is a string that contains the ID of a
  keystore, not the keystore config).
- **BREAKING**: Use simplified zcap revocation model via `revokeCapability`.
  Now any party that has delegated a zcap may revoke it by calling
  `revokeCapability` with the revoked zcap without passing an additional
  capability that targets a revocatio endpoint. If no capability is passed,
  then the client will a root zcap at the `<keystoreId>/revocations/<zcap ID>`
  endpoint. The controller for this target is expected to be the delegator
  of the zcap.
- **BREAKING**: `KmsClient` functions that previously returned
  base64url-encoded results will now base64url-decode and return a
  `Uint8Array` instead. The APIs for `AsymmetricKey` and `KeyAgreementKey` will
  not be changed as they already returned a `Uint8Array` (instead, the decoding
  will just be moved to KmsClient). However, `Hmac.sign()` and `Kek.wrapKey()`
  will now return a `Uint8Array`. This change moves all encoding decisions that
  are related to the WebKMS HTTP API only inside of the `KmsClient` for
  consistency.
- **BREAKING**: Require `suiteContextUrl` be passed to `KmsClient` along with
  the key type. This allows decoupling of this library from `crypto-ld`,
  enabling them to evolve independently. This library still supports a single
  recommended key algorithm per type of key when using `KeystoreAgent`, e.g.,
  `keyAgreement`, `kek`, `hmac`, `asymmetric`.
- **BREAKING**: Creating a keystore now requires an `invocationSigner` as
  the request signs a zcap for the keystore creation endpoint as its
  invocation target.

### Removed
- **BREAKING**: Remove `enableCapability` and `disableCapability`. To revoke a
  delegated authorized zcap, revoke it via `revokeCapability` instead.
- **BREAKING**: Remove built-in support for older keys
  (e.g., `Ed25519Signature2018`). These can still be generated if the WebKMS
  server supports them, but their `suiteContextUrl` must be passed to
  `KmsClient.generateKey()`, they are not supported via `KeystoreAgent`.
- **BREAKING**: Remove `keyType` option from `CapabilityAgent`.
- **BREAKING**: Remove `findKeystores` API. It was unused, would require
  changes to work with the other changes in this new version, and its unclear
  how much of a benefit it is at this time. A redesign of this API may come
  back in a future version if it makes sense to do so.

## 6.0.0 - 2021-05-04

### Changed
- Update dependencies.
  - **BREAKING**: Remove `security-context` and Use [webkms-context@1.0](https://github.com/digitalbazaar/webkms-context/blob/main/CHANGELOG.md).
  - Use [`aes-key-wrapping-2019-context@1.0.3`](https://github.com/digitalbazaar/aes-key-wrapping-2019-context/blob/main/CHANGELOG.md).
  - Use [`sha256-hmac-key-2019-context@1.0.3`](https://github.com/digitalbazaar/sha256-hmac-key-2019-context/blob/main/CHANGELOG.md).

## 5.0.1 - 2021-04-13

### Fixed
- Include `cryptoLd.js` file to files section in package.json.

## 5.0.0 - 2021-04-08

### Changed
- **BREAKING**: Rename NPM package from `webkms-client` to
  `@digitalbazaar/webkms-client`.
- Add support for multiple asymmetric key types (`Ed25519VerificationKey2018`,
  `Ed25519VerificationKey2020`, `X25519KeyAgreementKey2019`,
  `X25519KeyAgreementKey2020`) via `crypto-ld`.

## 4.0.0 - 2021-03-17

### Changed
- **BREAKING**: Switch from using `Ed25519VerificationKey2018` key types
  to `Ed25519VerificationKey2020` for capability signing.
  See [`crypto-ld v4`](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---2020-08-01)
  changelog.
  See also instructions on
  [converting and upgrading from Ed25519VerificationKey2018](https://github.com/digitalbazaar/ed25519-verification-key-2020#converting-from-previous-ed25519verificationkey2018-key-type)
- Remove `crypto-ld` as a dependency (it's still used by individual key suites).
- **BREAKING**: Drop support for Node 10 (it's moving out of LTS).

## 3.1.0 - 2021-03-08

### Added
- Add optional `defaultHeaders` parameter to the KmsClient constructor. This
  allows additional headers to be included with KMS requests.

## 3.0.0 - 2021-03-02

### Changed
- Use `http-signature-zcap-invoke@3`. Numerous breaking changes here related
  to dates in the http-signature header.

## 2.5.0 - 2021-03-02

### Added
- Implement KmsClient.updateKeystore API.
- Implement KeystoreAgent.updateConfig API.

## 2.4.0 - 2021-03-01

### Changed
- HMAC cache expiration is extended on `get`.

## 2.3.2 - 2020-09-30

### Fixed
- Move `crypto-ld` from devDependencies to dependencies.

## 2.3.1 - 2020-08-14

### Fixed
- Fix searchParams option httpClient.get API call.

## 2.3.0 - 2020-06-24

### Added
- Add an LRU cache to improve performance for HMAC operations.

## 2.2.0 - 2020-06-19

### Changed
- Use `@digitialbazaar/http-client` in place of `axios` for HTTP requests.

## 2.1.0 - 2020-04-21

### Added
- Setup CI and coverage workflow.

### Changed
- Update deps.

## 2.0.1 - 2020-02-10

### Changed
- Use zcap-invoke@1.1.1.

## 2.0.0 - 2020-02-07

### Added
- Add `revokeCapability` API.
- Add `CapabilityAgent`.
- Add `KeystoreAgent`.

### Removed
- **BREAKING**: Removed `ControllerKey` and replaced with `CapabilityAgent`
  and `KeystoreAgent`.

## 1.1.0 - 2020-01-11

### Added
- Allow `authorizations` zcaps.

## 1.0.0 - 2019-12-18

### Added
- Add core files.

- See git history for changes previous to this release.
