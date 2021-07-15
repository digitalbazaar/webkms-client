/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
import base64url from 'base64url-universal';
import {cryptoLd} from './cryptoLd.js';
import {httpClient, DEFAULT_HEADERS} from '@digitalbazaar/http-client';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';
import webkmsContext from 'webkms-context';
import aesContext from 'aes-key-wrapping-2019-context';
import hmacContext from 'sha256-hmac-key-2019-context';

const {CONTEXT_URL: WEBKMS_CONTEXT_URL} = webkmsContext;
const {CONTEXT_URL: AES_2019_CONTEXT_URL} = aesContext;
const {CONTEXT_URL: HMAC_2019_CONTEXT_URL} = hmacContext;

const symmetric = new Map([
  ['AesKeyWrappingKey2019', AES_2019_CONTEXT_URL],
  ['Sha256HmacKey2019', HMAC_2019_CONTEXT_URL]
]);

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
   * @param {string} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} The key description for the key.
   */
  async generateKey({type, capability, invocationSigner}) {
    _assert(type, 'type', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    let suiteContextUrl = symmetric.get(type);
    if(!suiteContextUrl) {
      ({SUITE_CONTEXT: suiteContextUrl} = cryptoLd.suites.get(type) || {});
      if(!suiteContextUrl) {
        throw new Error(`Unknown key type: "${type}".`);
      }
    }
    const operation = {
      '@context': [WEBKMS_CONTEXT_URL, suiteContextUrl],
      type: 'GenerateKeyOperation',
      invocationTarget: {type}
    };
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
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: operation, capability, invocationSigner,
        capabilityAction: 'generateKey'
      });
      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return result.data;
    } catch(e) {
      if(e.status === 409) {
        const err = new Error('Duplicate error.');
        err.name = 'DuplicateError';
        throw err;
      }
      throw e;
    }
  }

  /**
   * Gets the key description for the given key ID.
   *
   * @alias webkms.getKeyDescription
   *
   * @param {object} options - The options to use.
   * @param {string} [options.keyId] - The ID of the key.
   * @param {string} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} The key description.
   */
  async getKeyDescription({keyId, capability, invocationSigner}) {
    _assert(invocationSigner, 'invocationSigner', 'object');

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      _assert(keyId, 'keyId', 'string');
      capability = _getRootZcapId({keyId});
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'get', headers: this.defaultHeaders,
        capability, invocationSigner,
        capabilityAction: 'read'
      });
      // send request
      const {agent} = this;
      const result = await httpClient.get(url, {agent, headers});
      return result.data;
    } catch(e) {
      if(e.status === 404) {
        const err = new Error('Key description not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
    }
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
    if(!keystoreId && !(capability && typeof capability === 'object')) {
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

    const url = KmsClient._getInvocationTarget({capability}) ||
      `${keystoreId}/revocations/${encodeURIComponent(capabilityToRevoke.id)}`;
    if(!capability) {
      capability = `urn:zcap:root:${encodeURIComponent(url)}`;
    }
    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: capabilityToRevoke, capability, invocationSigner,
        capabilityAction: 'write'
      });
      // send request
      const {agent} = this;
      await httpClient.post(url, {agent, headers, json: capabilityToRevoke});
    } catch(e) {
      if(e.status === 409) {
        const err = new Error('Duplicate error.');
        err.name = 'DuplicateError';
        throw err;
      }
      throw e;
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
   * @param {string} [options.capability] - The zCAP-LD authorization
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
      '@context': WEBKMS_CONTEXT_URL,
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
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: operation, capability, invocationSigner,
        capabilityAction: 'wrapKey'
      });
      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return base64url.decode(result.data.wrappedKey);
    } catch(e) {
      if(e.status === 404) {
        const err = new Error('Key encryption key not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
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
   * @param {string} [options.capability] - The zCAP-LD authorization
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
      '@context': WEBKMS_CONTEXT_URL,
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
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: operation, capability, invocationSigner,
        capabilityAction: 'unwrapKey'
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
      if(e.status === 404) {
        const err = new Error('Key encryption key not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
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
   * @param {string} [options.capability] - The zCAP-LD authorization
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
      '@context': WEBKMS_CONTEXT_URL,
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
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: operation, capability, invocationSigner,
        capabilityAction: 'sign'
      });
      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return base64url.decode(result.data.signatureValue);
    } catch(e) {
      if(e.status === 404) {
        const err = new Error('Key not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
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
   * @param {string} [options.capability] - The zCAP-LD authorization
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
      '@context': WEBKMS_CONTEXT_URL,
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
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: operation, capability, invocationSigner,
        capabilityAction: 'verify'
      });
      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return result.data.verified;
    } catch(e) {
      if(e.status === 404) {
        const err = new Error('Key not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
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
   * @param {string} [options.capability] - The zCAP-LD authorization
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
      '@context': WEBKMS_CONTEXT_URL,
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
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: this.defaultHeaders,
        json: operation, capability, invocationSigner,
        capabilityAction: 'deriveSecret'
      });
      // send request
      const {agent} = this;
      const result = await httpClient.post(url, {
        agent, headers, json: operation
      });
      return base64url.decode(result.data.secret);
    } catch(e) {
      if(e.status === 404) {
        const err = new Error('Key agreement key not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
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
    const headers = await signCapabilityInvocation({
      url, method: 'post',
      headers: this.defaultHeaders,
      json: config,
      capability,
      invocationSigner,
      capabilityAction: 'write'
    });
    // send request
    const result = await httpClient.post(url, {agent, headers, json: config});

    return result.data;
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
    const headers = await signCapabilityInvocation({
      url, method: 'get',
      headers: this.defaultHeaders,
      capability,
      invocationSigner,
      capabilityAction: 'read'
    });
    // send request
    const result = await httpClient.get(url, {agent, headers});
    return result.data;
  }

  /**
   * Creates a new keystore using the given configuration.
   *
   * @alias webkms.createKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} options.url - The url to post the configuration to.
   * @param {string} options.config - The keystore's configuration.
   * @param {object} [options.httpsAgent] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the newly
   *   created keystore.
   */
  static async createKeystore({url = '/kms/keystores', config, httpsAgent}) {
    _assert(url, 'url', 'string');
    _assert(config, 'config', 'object');
    _assert(config.controller, 'config.controller', 'string');
    const result = await httpClient.post(url, {
      agent: httpsAgent, json: config
    });
    return result.data;
  }

  /**
   * Finds the configuration for a keystore by its controller and reference ID.
   *
   * @alias webkms.findKeystore
   *
   * @param {object} options - The options to use.
   * @param {string} [options.url] - The url to query.
   * @param {string} options.controller - The keystore's controller.
   * @param {string} options.referenceId - The keystore's reference ID.
   * @param {object} [options.httpsAgent] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the keystore.
   */
  // FIXME: consider removal; if not removed, add `capability` and
  // `invocationSigner` and invoke zcap to perform query
  /*static async findKeystore(
    {url = '/kms/keystores', controller, referenceId, httpsAgent}) {
    _assert(controller, 'controller', 'string');
    _assert(referenceId, 'referenceId', 'string');
    const result = await httpClient.get(url, {
      agent: httpsAgent,
      searchParams: {controller, referenceId},
    });
    return result.data[0] || null;
  }*/

  static _getInvocationTarget({capability}) {
    if(!(capability && typeof capability === 'object')) {
      // no capability provided
      return null;
    }
    let result;
    const {invocationTarget} = capability;
    if(invocationTarget && typeof invocationTarget === 'object') {
      result = invocationTarget.id;
    } else {
      result = invocationTarget;
    }
    if(typeof result !== 'string') {
      throw new TypeError('"capability.invocationTarget" is invalid.');
    }
    return result;
  }
}

async function _assert(variable, name, types) {
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
  return `urn:zcap:root:${encodeURIComponent(suffix)}`;
}
