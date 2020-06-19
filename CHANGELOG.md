# webkms-client ChangeLog

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
