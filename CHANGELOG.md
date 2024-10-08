# webkms-client ChangeLog

## 14.1.2 - 2024-09-19

### Fixed
- Allow `zUC6` multibase header for `Bls12381G2` keys.

## 14.1.1 - 2024-07-10

### Added
- Assert `KmsClient.createKeystore()` return value is well-formed.

## 14.1.0 - 2024-04-12

### Added
- Add support for BLS12-381 keys.

## 14.0.0 - 2024-01-24

### Changed
- **BREAKING**: Remove contexts from WebKMS payloads. WebKMS payloads are
  now treated as JSON instead of JSON-LD invocation of a method must be
  done using an authz mechanism that treats operations as such, e.g., zcap
  invocation using HTTP signatures.

## 13.0.1 - 2023-09-20

### Fixed
- Assign `cause.data` to `error.data` in `_handleClientError` helper.
  `error.data` was inadvertently removed in `v12.1.2`.

## 13.0.0 - 2023-09-13

### Changed
- **BREAKING**: Drop support for Node.js < 18.
- Use `@digitalbazaar/http-client@4` which requires Node.js 18+.

## 12.1.2 - 2023-09-12

### Fixed
- Do not overwrite an existing `error.cause` value.
- Utilize the `message` parameter passed to the `_handleClientError` helper.

## 12.1.1 - 2023-08-22

### Fixed
- Ensure that when using a root zcap with `fromCapability` static helper
  functions, the invocation target is calculated correctly.

## 12.1.0 - 2022-09-15

### Added
- `AsymmetricKey` now sets `algorithm` using the prefix of the
  `publicKeyMultibase`.

## 12.0.0 - 2022-08-02

### Removed
- Remove `CapabilityAgent` seed cache feature (including `fromCache` API). It
  is typically (if not always) unused and unnecessary; removing it reduces
  attack surface.

## 11.1.0 - 2022-08-02

### Added
- Enable passing `capability` as an option to `KeystoreAgent.generateKey`.

## 11.0.0 - 2022-06-09

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- **BREAKING**: Use `globalThis` for browser crypto and streams.
- **BREAKING**: Require Web Crypto API. Older browsers and Node.js 14 users
  need to install an appropriate polyfill.
- Update dependencies.
- Lint module.

## 10.0.0 - 2022-03-01

### Changed
- **BREAKING**: Better future proof zcap endpoints by posting zcap
  revocations to `/zcaps/revocations` instead of just `/revocations`.

## 9.3.0 - 2022-02-27

### Added
- Allow `kmsId` to be set in `Hmac` instances (and default to `id`) for
  consistency with other keys.

### Changed
- Change underlying cache implementation in `Hmac` to use
  `@digitalbazaar/lru-memoize` to improve maintainability and code reuse.

### Fixed
- Ensure `cache` is marked as a private member `_cache` of `Hmac`.

## 9.2.1 - 2022-02-16

### Fixed
- Fix missing `cause` param.

## 9.2.0 - 2022-02-02

### Fixed
- Fix `fromCapability` static helper functions so that a default `KmsClient`
  instance will be created to match the documentation.

## 9.1.0 - 2022-01-14

### Added
- Allow `maxCapabilityChainLength` to be specified when generating a key. This
  field can be used to express the maximum acceptable length of a capability
  chain associated with a capability invocation at an invocation target, i.e.,
  at a key URL.

## 9.0.0 - 2022-01-11

### Changed
- **BREAKING**: Key constructors cannot be called directly when using a
  `capability`. Instead, call `.fromCapability` on the appropriate key class.
  This change allows key instances to be created asynchronously, which is
  necessary to obtain public key description information prior to using an
  asymmetric key to sign.
- **BREAKING**: `generateKey` now returns `{keyId, keyDescription}`. This
  provides the KMS ID for the key along with whatever `id` is set in the
  key description, which is the `id` for the public key (which may be
  different) from the KMS key ID.

## 8.0.1 - 2021-12-09

### Fixed
- Fix `headers` and `method` passed into `signCapabilityInvocation()`
  in `createKeystore()` and `getKeystore()`.

## 8.0.0 - 2021-12-01

### Changed
- **BREAKING**: Update error messages, make them more specific.
  Add `cause` property to the thrown errors, and include `requestUrl` for
  timeout and network errors.

## 7.0.1 - 2021-08-27

### Fixed
- Fix internal `_assert` helper; it should have been synchronous
  but was marked async.

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
  capability that targets a revocation endpoint. If no capability is passed,
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
