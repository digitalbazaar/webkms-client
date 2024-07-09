/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {DEFAULT_HEADERS, httpClient} from '@digitalbazaar/http-client';
import {LruCache} from '@digitalbazaar/lru-memoize';
import {signCapabilityInvocation} from
  '@digitalbazaar/http-signature-zcap-invoke';

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

// process-wide shared cache for key descriptions:
const KEY_DESCRIPTION_CACHE = new LruCache({
  // 1000 keys at ~1 KiB each would be only ~1 MiB cache size
  max: 1000,
  // 5 min TTL (key descriptions rarely, if ever, change)
  maxAge: 1000 * 60 * 5
});

/**
 * @class
 * @classdesc A WebKMS Client used to interface with a KMS.
 * @memberof module:webkms
 */
export class KmsClient {
  /**
   * Creates a new KmsClient.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.keystoreId] - The ID of the keystore
   *   that must be a URL that refers to the keystore's root storage
   *   location; if not given, then a separate capability must be given to
   *   each method called on the client instance.
   * @param {object} [options.httpsAgent] - A Node.js `https.Agent` instance
   *   to use when making requests.
   * @param {object} [options.defaultHeaders] - The HTTP headers to include
   *   with every request.
   *
   * @returns {KmsClient} The new instance.
   */
  constructor({keystoreId, httpsAgent, defaultHeaders} = {}) {
    if(keystoreId) {
      _assert(keystoreId, 'keystoreId', 'string');
    }
    this.keystoreId = keystoreId;
    this.agent = httpsAgent;
    this.defaultHeaders = {...DEFAULT_HEADERS, ...defaultHeaders};
  }

  /**
   * Generates a new cryptographic key in the keystore.
   *
   * @alias webkms.generateKey
   *
   * @param {object} options - The options to use.
   * @param {string} options.type - The key type (e.g. 'AesKeyWrappingKey2019',
   *   or 'Ed25519VerificationKey2020').
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * @param {string} [options.maxCapabilityChainLength] - The max acceptable
   *   length of a capability chain associated with a zcap invocation at
   *   the key's URL.
   * @param {string} [options.publicAlias] - The public alias to use for the
   *   key, if it is an asymmetric key.
   * @param {string} [options.publicAliasTemplate] - The public alias template
   *   to use for the key, if it is an asymmetric key.
   *
   * @returns {Promise<object>} The new key ID and key description for the key.
   */
  async generateKey({
    type, capability, invocationSigner,
    maxCapabilityChainLength, publicAlias, publicAliasTemplate
  }) {
    _assert(type, 'type', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');
    if(maxCapabilityChainLength !== undefined &&
      !(typeof maxCapabilityChainLength === 'number' &&
      maxCapabilityChainLength >= 1 &&
      maxCapabilityChainLength <= 10)) {
      throw new Error(
        '"maxCapabilityChainLength" must be an integer between 1 and 10.');
    }
    if(publicAlias !== undefined) {
      _assert(publicAlias, 'publicAlias', 'string');
    }
    if(publicAliasTemplate !== undefined) {
      _assert(publicAliasTemplate, 'publicAliasTemplate', 'string');
    }
    if(publicAlias && publicAliasTemplate) {
      throw new Error(
        'Only one of "publicAlias" and "publicAliasTemplate" may be given.');
    }

    const operation = {
      type: 'GenerateKeyOperation',
      invocationTarget: {type}
    };
    if(maxCapabilityChainLength) {
      operation.invocationTarget.maxCapabilityChainLength =
        maxCapabilityChainLength;
    }
    if(publicAlias) {
      operation.invocationTarget.publicAlias = publicAlias;
    } else if(publicAliasTemplate) {
      operation.invocationTarget.publicAliasTemplate = publicAliasTemplate;
    }

    // determine url from capability or use defaults
    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      const {keystoreId} = this;
      url = `${keystoreId}/keys`;
      capability = _getRootZcapId({keystoreId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: operation,
        capability, invocationSigner, capabilityAction: 'generateKey'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return result.data;
    } catch(e) {
      let cause;
      if(e.status === 409) {
        cause = new Error('Duplicate error.');
        cause.name = 'DuplicateError';
        cause.cause = e;
      } else {
        cause = e;
      }

      _handleClientError({
        message: 'Error generating key.',
        cause
      });
    }
  }

  /**
   * Gets the key description for the given key ID.
   *
   * @alias webkms.getKeyDescription
   *
   * @param {object} options - The options to use.
   * @param {string} [options.keyId] - The ID of the key.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * @param {boolean} [options.useCache=true] - `true` to use a cache when
   *   retrieving the key description, `false` not to.
   *
   * @returns {Promise<object>} The key description.
   */
  async getKeyDescription({
    keyId, capability, invocationSigner, useCache = true
  }) {
    _assert(invocationSigner, 'invocationSigner', 'object');

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      _assert(keyId, 'keyId', 'string');
      capability = _getRootZcapId({keyId});
    }

    if(!useCache) {
      return this._getUncachedKeyDescription(
        {url, capability, invocationSigner});
    }

    return KEY_DESCRIPTION_CACHE.memoize({
      key: JSON.stringify(
        [url, capability.id || capability, invocationSigner.id]),
      fn: () => this._getUncachedKeyDescription(
        {url, capability, invocationSigner})
    });
  }

  /**
   * Revoke a delegated capability.
   *
   * @alias webkms.revokeCapability
   *
   * @param {object} options - The options to use.
   * @param {object} options.capabilityToRevoke - The capability to revoke.
   * @param {string} [options.capability] - The zcap authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves once the operation completes.
   */
  async revokeCapability({capabilityToRevoke, capability, invocationSigner}) {
    _assert(capabilityToRevoke, 'capabilityToRevoke', 'object');
    _assert(invocationSigner, 'invocationSigner', 'object');

    let {keystoreId} = this;
    if(!keystoreId && !capability) {
      // since no `keystoreId` was set and no `capability` with an invocation
      // target that can be parsed was given, get the keystore ID from the
      // capability that is to be revoked -- presuming it is a WebKMS key (if
      // revoking any other capability, the `keystoreId` must be set or a
      // `capability` passed to invoke)
      const invocationTarget = KmsClient._getInvocationTarget(
        {capability: capabilityToRevoke});
      const idx = invocationTarget.lastIndexOf('/keys/');
      if(idx === -1) {
        throw new Error(
          `Invalid WebKMS key invocation target (${invocationTarget}).`);
      }
      keystoreId = invocationTarget.substr(0, idx);
    }

    const revokePath = `${keystoreId}/zcaps/revocations`;
    const url = KmsClient._getInvocationTarget({capability}) ||
      `${revokePath}/${encodeURIComponent(capabilityToRevoke.id)}`;
    if(!capability) {
      capability = `${ZCAP_ROOT_PREFIX}${encodeURIComponent(url)}`;
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: capabilityToRevoke, capability, invocationSigner,
        capabilityAction: 'write'
      });

      // send request
      const {agent} = this;
      await httpClient.post(url, {agent, headers, json: capabilityToRevoke});
    } catch(e) {
      let cause;
      if(e.status === 409) {
        cause = new Error('Duplicate error.');
        cause.name = 'DuplicateError';
        cause.cause = e;
      } else {
        cause = e;
      }

      _handleClientError({
        message: 'Error revoking zCap.',
        notFoundMessage: 'zCap not found.',
        cause
      });
    }
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @alias webkms.wrapKey
   *
   * @param {object} options - The options to use.
   * @param {string} options.kekId - The ID of the wrapping key to use.
   * @param {Uint8Array} options.unwrappedKey - The unwrapped key material as
   *   a Uint8Array.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The wrapped key bytes.
   */
  async wrapKey({kekId, unwrappedKey, capability, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(unwrappedKey, 'unwrappedKey', 'Uint8Array');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      type: 'WrapKeyOperation',
      invocationTarget: kekId,
      unwrappedKey: base64url.encode(unwrappedKey)
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = kekId;
      capability = _getRootZcapId({keyId: kekId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: operation,
        capability, invocationSigner, capabilityAction: 'wrapKey'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return base64url.decode(result.data.wrappedKey);
    } catch(e) {
      _handleClientError({
        message: 'Error wrapping key.',
        notFoundMessage: 'Key encryption key not found.',
        cause: e
      });
    }
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @alias webkms.unwrapKey
   *
   * @param {object} options - The options to use.
   * @param {string} options.kekId - The ID of the unwrapping key to use.
   * @param {Uint8Array|string} options.wrappedKey - The wrapped key material
   *   as a Uint8Array or base64url-encoded string.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array|null>} Resolves to the unwrapped key material
   *   or null if the unwrapping failed because the key did not match.
   */
  async unwrapKey({kekId, wrappedKey, capability, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(wrappedKey, 'wrappedKey', ['string', 'Uint8Array']);
    _assert(invocationSigner, 'invocationSigner', 'object');

    if(wrappedKey instanceof Uint8Array) {
      // base64url-encode wrappedKey for transport
      wrappedKey = base64url.encode(wrappedKey);
    }

    const operation = {
      type: 'UnwrapKeyOperation',
      invocationTarget: kekId,
      wrappedKey
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = kekId;
      capability = _getRootZcapId({keyId: kekId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: operation,
        capability, invocationSigner, capabilityAction: 'unwrapKey'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      if(result.data.unwrappedKey === null) {
        return null;
      }
      return base64url.decode(result.data.unwrappedKey);
    } catch(e) {
      _handleClientError({
        message: 'Error unwrapping key.',
        notFoundMessage: 'Key encryption key not found.',
        cause: e
      });
    }
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @alias webkms.sign
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The signature.
   */
  async sign({keyId, data, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      type: 'SignOperation',
      invocationTarget: keyId,
      verifyData: base64url.encode(data)
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = keyId;
      capability = _getRootZcapId({keyId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: operation,
        capability, invocationSigner, capabilityAction: 'sign'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return base64url.decode(result.data.signatureValue);
    } catch(e) {
      _handleClientError({
        message: 'Error during "sign" operation.',
        cause: e
      });
    }
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @alias webkms.verify
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to verify as a Uint8Array.
   * @param {Uint8Array|string} options.signature - The signature to verify;
   *   it may be passed either a base64url-encoded string or a Uint8Array.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({keyId, data, signature, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(signature, 'signature', ['string', 'Uint8Array']);
    _assert(invocationSigner, 'invocationSigner', 'object');

    if(signature instanceof Uint8Array) {
      // base64url-encode signature for transport
      signature = base64url.encode(signature);
    }

    const operation = {
      type: 'VerifyOperation',
      invocationTarget: keyId,
      verifyData: base64url.encode(data),
      signatureValue: signature
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = keyId;
      capability = _getRootZcapId({keyId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: operation,
        capability, invocationSigner, capabilityAction: 'verify'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return result.data.verified;
    } catch(e) {
      _handleClientError({
        message: 'Error during "verify" operation.',
        cause: e
      });
    }
  }

  /**
   * Derives a shared secret via the given peer public key, typically for use
   * as one parameter for computing a shared key. It should not be used as
   * a shared key itself, but rather input into a key derivation function (KDF)
   * to produce a shared key.
   *
   * @alias webkms.deriveSecret
   *
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the key agreement key to use.
   * @param {object} options.publicKey - The public key to compute the shared
   *   secret against; the public key type must match the key agreement key's
   *   type.
   * @param {string} [options.capability] - The authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The shared secret bytes.
   */
  async deriveSecret({keyId, publicKey, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(publicKey, 'publicKey', 'object');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      type: 'DeriveSecretOperation',
      invocationTarget: keyId,
      publicKey
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = keyId;
      capability = _getRootZcapId({keyId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: operation,
        capability, invocationSigner, capabilityAction: 'deriveSecret'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return base64url.decode(result.data.secret);
    } catch(e) {
      _handleClientError({
        message: 'Error during "deriveSecret" operation.',
        notFoundMessage: 'Key agreement key not found.',
        cause: e
      });
    }
  }

  /**
   * Update a keystore using the given configuration.
   *
   * @alias webkms.updateKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} [options.capability] - The ZCAP authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {string} options.config - The keystore's configuration.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves to the new keystore configuration.
   */
  async updateKeystore({capability, config, invocationSigner}) {
    const {keystoreId, agent} = this;
    if(!(keystoreId || capability)) {
      throw new TypeError(
        '"capability" is required if "keystoreId" was not provided ' +
        'to the KmsClient constructor.');
    }
    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = keystoreId;
      capability = _getRootZcapId({keystoreId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders, json: config,
        capability, invocationSigner, capabilityAction: 'write'
      });

      // send request
      const result = await httpClient.post(url, {
        agent, headers, json: config
      });
      return result.data;
    } catch(e) {
      _handleClientError({
        message: 'Error during "update keystore" operation.',
        cause: e
      });
    }
  }

  /**
   * Gets the configuration for a keystore by its ID.
   *
   * @alias webkms.getKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} [options.capability] - The ZCAP authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves to the configuration for the keystore.
   */
  async getKeystore({capability, invocationSigner}) {
    _assert(invocationSigner, 'invocationSigner', 'object');

    const {keystoreId, agent} = this;
    if(!(keystoreId || capability)) {
      throw new TypeError(
        '"capability" is required if "keystoreId" was not provided ' +
        'to the KmsClient constructor.');
    }

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = keystoreId;
      capability = _getRootZcapId({keystoreId});
    }

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'get', headers: this.defaultHeaders,
        capability, invocationSigner, capabilityAction: 'read'
      });

      // send request
      const result = await httpClient.get(url, {agent, headers});
      return result.data;
    } catch(e) {
      _handleClientError({
        message: 'Error during "get keystore" operation.',
        cause: e
      });
    }
  }

  /**
   * Creates a new keystore using the given configuration.
   *
   * @alias webkms.createKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} options.url - The url to post the configuration to.
   * @param {string} options.config - The keystore's configuration.
   * @param {string|object} [options.capability] - The zcap authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * @param {object} [options.httpsAgent] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the newly
   *   created keystore.
   */
  static async createKeystore({
    url, config, capability, invocationSigner, httpsAgent,
  } = {}) {
    _assert(url, 'url', 'string');
    _assert(config, 'config', 'object');
    _assert(config.controller, 'config.controller', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    if(capability) {
      if(!url) {
        url = KmsClient._getInvocationTarget({capability});
      }
    } else {
      capability = `${ZCAP_ROOT_PREFIX}${encodeURIComponent(url)}`;
    }

    let result;
    try {
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS, json: config,
        capability, invocationSigner, capabilityAction: 'write'
      });

      const agent = httpsAgent || this.agent;
      // send request
      result = await httpClient.post(url, {
        agent, headers, json: config
      });
    } catch(e) {
      _handleClientError({
        message: 'Error during "create keystore" operation.',
        cause: e
      });
    }

    _assert(result.data, 'result.data', 'object');
    _assert(result.data.id, 'result.data.id', 'string');
    return result.data;
  }

  async _getUncachedKeyDescription({url, capability, invocationSigner}) {
    _assert(invocationSigner, 'invocationSigner', 'object');

    try {
      const headers = await signCapabilityInvocation({
        url, method: 'get', headers: this.defaultHeaders,
        capability, invocationSigner, capabilityAction: 'read'
      });

      // send request
      const {agent} = this;
      const result = await httpClient.get(url, {agent, headers});
      return result.data;
    } catch(e) {
      _handleClientError({
        message: 'Error fetching key description.',
        notFoundMessage: 'Key description not found.',
        cause: e
      });
    }
  }

  static _getInvocationTarget({capability}) {
    // no capability, so no invocation target
    if(capability === undefined || capability === null) {
      return null;
    }

    let invocationTarget;
    if(typeof capability === 'string') {
      if(!capability.startsWith(ZCAP_ROOT_PREFIX)) {
        throw new Error(
          'If "capability" is a string, it must be a root capability.');
      }
      invocationTarget = decodeURIComponent(
        capability.substring(ZCAP_ROOT_PREFIX.length));
    } else if(typeof capability === 'object') {
      ({invocationTarget} = capability);
    }

    if(!(typeof invocationTarget === 'string' &&
      invocationTarget.startsWith('https://'))) {
      throw new TypeError(
        '"invocationTarget" from capability must be an "https" URL.');
    }

    return invocationTarget;
  }
}

/**
 * @param {object} options - Options hashmap.
 * @param {string} options.message - Error message.
 * @param {Error} options.cause - Source error for wrapping.
 * @param {string} [options.notFoundMessage] - Optional 'not found' message.
 */
function _handleClientError({
  message, cause, notFoundMessage = 'Key not found'
}) {
  let error;
  const errorMessage = message.slice(0, -1);
  if(cause.status === 404) {
    // e.g. 'Error getting key description: Key description not found'
    error = new Error(`${errorMessage}: ${notFoundMessage}`);
    error.status = 404;
  } else {
    error = new Error(`WebKMS client error: ${errorMessage}`);
    if(cause.data) {
      error.data = cause.data;
    }
    if(cause.status) {
      error.status = cause.status;
    }
  }

  if(!error.message.endsWith('.')) {
    error.message += '.';
  }

  error.cause = cause;

  throw error;
}

function _assert(variable, name, types) {
  if(!Array.isArray(types)) {
    types = [types];
  }
  const type = variable instanceof Uint8Array ? 'Uint8Array' : typeof variable;
  if(!types.includes(type)) {
    throw new TypeError(
      `"${name}" must be ${types.length === 1 ? 'a' : 'one of'} ` +
      `${types.join(', ')}.`);
  }
}

function _getRootZcapId({keystoreId, keyId}) {
  let suffix;
  if(keyId) {
    const idx = keyId.lastIndexOf('/keys/');
    if(idx === -1) {
      throw new Error(`Invalid WebKMS key ID (${keyId}).`);
    }
    suffix = keyId.substr(0, idx);
  } else {
    suffix = keystoreId;
  }
  return `${ZCAP_ROOT_PREFIX}${encodeURIComponent(suffix)}`;
}
