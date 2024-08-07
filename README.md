# WebKMS Client _(@digitalbazaar/webkms-client)_

[![Build Status](https://img.shields.io/github/actions/workflow/status/digitalbazaar/webkms-client/main.yml)](https://github.com/digitalbazaar/webkms-client/actions/workflows/main.yml)
[![Coverage status](https://img.shields.io/codecov/c/github/digitalbazaar/webkms-client)](https://codecov.io/gh/digitalbazaar/webkms-client)
[![NPM Version](https://img.shields.io/npm/v/@digitalbazaar/webkms-client.svg)](https://npm.im/@digitalbazaar/webkms-client)

> A JavaScript WebKMS client library.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

See also related specs:

* [W3C CCG Latest Draft](https://w3c-ccg.github.io/webkms/)

## Security

TBD

## Install

- Browsers and Node.js 18+ are supported.
- [Web Crypto API][] required. Older browsers must use a polyfill.

### NPM

To install via NPM:

```
npm install @digitalbazaar/webkms-client
```

### Development

To install locally (for development):

```
git clone https://github.com/digitalbazaar/webkms-client.git
cd webkms-client
npm install
```

## Usage
### Modules

<dl>
<dt><a href="#module_webkms">webkms</a></dt>
<dd><p>WebKMS client for Javascript.</p>
</dd>
</dl>

### Functions

<dl>
<dt><a href="#webkms_generateKey">webkms:generateKey(options)</a> ⇒ <code>Promise.&lt;object&gt;</code></dt>
<dd><p>Generates a new cryptographic key in the keystore.</p>
</dd>
<dt><a href="#webkms_getKeyDescription">webkms:getKeyDescription(options)</a> ⇒ <code>Promise.&lt;object&gt;</code></dt>
<dd><p>Gets the key description for the given key ID.</p>
</dd>
<dt><a href="#webkms_revokeCapability">webkms:revokeCapability(options)</a> ⇒ <code>Promise.&lt;object&gt;</code></dt>
<dd><p>Store a capability revocation.</p>
</dd>
<dt><a href="#webkms_wrapKey">webkms:wrapKey(options)</a> ⇒ <code>Promise.&lt;Uint8Array&gt;</code></dt>
<dd><p>Wraps a cryptographic key using a key encryption key (KEK).</p>
</dd>
<dt><a href="#webkms_unwrapKey">webkms:unwrapKey(options)</a> ⇒ <code>Promise.&lt;(Uint8Array|null)&gt;</code></dt>
<dd><p>Unwraps a cryptographic key using a key encryption key (KEK).</p>
</dd>
<dt><a href="#webkms_sign">webkms:sign(options)</a> ⇒ <code>Promise.&lt;Uint8Array&gt;</code></dt>
<dd><p>Signs some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.</p>
</dd>
<dt><a href="#webkms_verify">webkms:verify(options)</a> ⇒ <code>Promise.&lt;boolean&gt;</code></dt>
<dd><p>Verifies some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.</p>
</dd>
<dt><a href="#webkms_deriveSecret">webkms:deriveSecret(options)</a> ⇒ <code>Promise.&lt;Uint8Array&gt;</code></dt>
<dd><p>Derives a shared secret via the given peer public key, typically for use
as one parameter for computing a shared key. It should not be used as
a shared key itself, but rather input into a key derivation function (KDF)
to produce a shared key.</p>
</dd>
<dt><a href="#webkms_createKeystore">webkms:createKeystore(options)</a> ⇒ <code>Promise.&lt;object&gt;</code></dt>
<dd><p>Creates a new keystore using the given configuration.</p>
</dd>
<dt><a href="#webkms_getKeystore">webkms:getKeystore(options)</a> ⇒ <code>Promise.&lt;object&gt;</code></dt>
<dd><p>Gets the configuration for a keystore by its ID.</p>
</dd>
</dl>

<a name="module_webkms"></a>

### webkms
WebKMS client for Javascript.


* [webkms](#module_webkms)
    * [.KmsClient](#module_webkms.exports.KmsClient)
        * [new exports.KmsClient(options)](#new_module_webkms.exports.KmsClient_new)

<a name="module_webkms.exports.KmsClient"></a>

### webkms.KmsClient
A WebKMS Client used to interface with a KMS.

**Kind**: instance class of [<code>webkms</code>](#module_webkms)
<a name="new_module_webkms.exports.KmsClient_new"></a>

#### new exports.KmsClient(options)
Creates a new KmsClient.

**Returns**: <code>KmsClient</code> - The new instance.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| [options.keystore] | <code>string</code> | The ID of the keystore   that must be a URL that refers to the keystore's root storage   location; if not given,   then a separate capability must be given to each method called on the   client instance. |
| [options.httpsAgent] | <code>object</code> | An optional   node.js `https.Agent` instance to use when making requests. |

<a name="webkms_generateKey"></a>

### webkms:generateKey(options) ⇒ <code>Promise.&lt;object&gt;</code>
Generates a new cryptographic key in the keystore.

**Kind**: global function
**Returns**: <code>Promise.&lt;object&gt;</code> - The key description for the key.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.kmsModule | <code>string</code> | The KMS module to use. |
| options.type | <code>string</code> | The key type (e.g. 'AesKeyWrappingKey2019'). |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_getKeyDescription"></a>

### webkms:getKeyDescription(options) ⇒ <code>Promise.&lt;object&gt;</code>
Gets the key description for the given key ID.

**Kind**: global function
**Returns**: <code>Promise.&lt;object&gt;</code> - The key description.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| [options.keyId] | <code>string</code> | The ID of the key. |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_revokeCapability"></a>

### webkms:revokeCapability(options) ⇒ <code>Promise.&lt;object&gt;</code>
Store a capability revocation.

**Kind**: global function
**Returns**: <code>Promise.&lt;object&gt;</code> - Resolves once the operation completes.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.capabilityToRevoke | <code>object</code> | The capability to revoke. |
| [options.capability] | <code>string</code> | The zcap authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_wrapKey"></a>

### webkms:wrapKey(options) ⇒ <code>Promise.&lt;Uint8Array&gt;</code>
Wraps a cryptographic key using a key encryption key (KEK).

**Kind**: global function
**Returns**: <code>Promise.&lt;Uint8Array&gt;</code> - The wrapped key bytes.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.kekId | <code>string</code> | The ID of the wrapping key to use. |
| options.unwrappedKey | <code>Uint8Array</code> | The unwrapped key material as   a Uint8Array. |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_unwrapKey"></a>

### webkms:unwrapKey(options) ⇒ <code>Promise.&lt;(Uint8Array\|null)&gt;</code>
Unwraps a cryptographic key using a key encryption key (KEK).

**Kind**: global function
**Returns**: <code>Promise.&lt;(Uint8Array\|null)&gt;</code> - Resolves to the unwrapped key material
  or null if the unwrapping failed because the key did not match.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.kekId | <code>string</code> | The ID of the unwrapping key to use. |
| options.wrappedKey | <code>string</code> | The wrapped key material as a   base64url-encoded string. |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_sign"></a>

### webkms:sign(options) ⇒ <code>Promise.&lt;Uint8Array&gt;</code>
Signs some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: global function
**Returns**: <code>Promise.&lt;Uint8Array&gt;</code> - The signature.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The ID of the signing key to use. |
| options.data | <code>Uint8Array</code> | The data to sign as a Uint8Array. |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_verify"></a>

### webkms:verify(options) ⇒ <code>Promise.&lt;boolean&gt;</code>
Verifies some data. Note that the data will be sent to the server, so if
this data is intended to be secret it should be hashed first. However,
hashing the data first may present interoperability issues so choose
wisely.

**Kind**: global function
**Returns**: <code>Promise.&lt;boolean&gt;</code> - `true` if verified, `false` if not.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The ID of the signing key to use. |
| options.data | <code>Uint8Array</code> | The data to verify as a Uint8Array. |
| options.signature | <code>string</code> | The base64url-encoded signature to   verify. |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_deriveSecret"></a>

### webkms:deriveSecret(options) ⇒ <code>Promise.&lt;Uint8Array&gt;</code>
Derives a shared secret via the given peer public key, typically for use
as one parameter for computing a shared key. It should not be used as
a shared key itself, but rather input into a key derivation function (KDF)
to produce a shared key.

**Kind**: global function
**Returns**: <code>Promise.&lt;Uint8Array&gt;</code> - The shared secret bytes.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.keyId | <code>string</code> | The ID of the key agreement key to use. |
| options.publicKey | <code>object</code> | The public key to compute the shared   secret against; the public key type must match the key agreement key's   type. |
| [options.capability] | <code>string</code> | The authorization   capability to use to authorize the invocation of this operation. |
| options.invocationSigner | <code>object</code> | An API with an   `id` property and a `sign` function for signing a capability invocation. |

<a name="webkms_createKeystore"></a>

### webkms:createKeystore(options) ⇒ <code>Promise.&lt;object&gt;</code>
Creates a new keystore using the given configuration.

**Kind**: global function
**Returns**: <code>Promise.&lt;object&gt;</code> - Resolves to the configuration for the newly
  created keystore.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.url | <code>string</code> | The url to post the configuration to. |
| options.config | <code>string</code> | The keystore's configuration. |
| [options.httpsAgent] | <code>object</code> | An optional   node.js `https.Agent` instance to use when making requests. |

<a name="webkms_getKeystore"></a>

### webkms:getKeystore(options) ⇒ <code>Promise.&lt;object&gt;</code>
Gets the configuration for a keystore by its ID.

**Kind**: global function
**Returns**: <code>Promise.&lt;object&gt;</code> - Resolves to the configuration for the keystore.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| options.id | <code>string</code> | The keystore's ID. |
| [options.httpsAgent] | <code>object</code> | An optional   node.js `https.Agent` instance to use when making requests. |

<a name="webkms_findKeystore"></a>

### webkms:findKeystore(options) ⇒ <code>Promise.&lt;object&gt;</code>
Finds the configuration for a keystore by its controller and reference ID.

**Kind**: global function
**Returns**: <code>Promise.&lt;object&gt;</code> - Resolves to the configuration for the keystore.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options to use. |
| [options.url] | <code>string</code> | The url to query. |
| options.controller | <code>string</code> | The keystore's controller. |
| [options.httpsAgent] | <code>object</code> | An optional   node.js `https.Agent` instance to use when making requests. |

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar

[Web Crypto API]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
