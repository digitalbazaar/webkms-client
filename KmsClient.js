/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import base64url from 'base64url-universal';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';

const SECURITY_CONTEXT_V2_URL = 'https://w3id.org/security/v2';
const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};

/**
 * A node https module.
 *
 * @typedef {object} https
 * @see https://nodejs.org/docs/latest-v11.x/api/https.html
 */

export class KmsClient {
  /**
   * Creates a new KmsClient.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.keystore=undefined] - The ID of the keystore
   * that must be a URL that refers to the keystore's root storage
   * location; if not given,
   *   then a separate capability must be given to each method called on the
   *   client instance.
   * @param {https.Agent} [options.httpsAgent=undefined] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {KmsClient} The new instance.
   */
  constructor({keystore, httpsAgent} = {}) {
    this.keystore = keystore;
    this.httpsAgent = httpsAgent;
  }

  /**
   * Generates a new cryptographic key in the keystore.
   *
   * @param {object} options - The options to use.
   * @param {string} options.kmsModule - The KMS module to use.
   * @param {string} options.type - The key type (e.g. 'AesKeyWrappingKey2019').
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} The key description for the key.
   */
  async generateKey({kmsModule, type, capability, invocationSigner}) {
    _assert(kmsModule, 'kmsModule', 'string');
    _assert(type, 'type', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      '@context': SECURITY_CONTEXT_V2_URL,
      type: 'GenerateKeyOperation',
      invocationTarget: {type, controller: invocationSigner.id},
      kmsModule
    };

    // determine url from capability or use defaults
    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = `${this.keystore}/keys`;
      capability = `${this.keystore}/zcaps/keys`;
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'generateKey'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
      return response.data;
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 409) {
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
   * @param {object} options - The options to use.
   * @param {string} [options.keyId] - The ID of the key.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
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
      url = capability = keyId;
    }

    let response;
    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'get', headers: DEFAULT_HEADERS,
        capability, invocationSigner,
        capabilityAction: 'read'
      });
      // send request
      const {httpsAgent} = this;
      response = await axios.get(url, {headers, httpsAgent});
    } catch(e) {
      response = e.response || {};
      if(response.status === 404) {
        const err = new Error('Key description not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
    }
    return response.data;
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {object} options - The options to use.
   * @param {string} options.kekId - The ID of the wrapping key to use.
   * @param {Uint8Array} options.unwrappedKey - The unwrapped key material as
   *   a Uint8Array.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<string>} The base64url-encoded wrapped key bytes.
   */
  async wrapKey({kekId, unwrappedKey, capability, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(unwrappedKey, 'unwrappedKey', 'Uint8Array');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      '@context': SECURITY_CONTEXT_V2_URL,
      type: 'WrapKeyOperation',
      invocationTarget: kekId,
      unwrappedKey: base64url.encode(unwrappedKey)
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = capability = kekId;
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'wrapKey'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
      return response.data.wrappedKey;
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 404) {
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
   * @param {object} options - The options to use.
   * @param {string} options.kekId - The ID of the unwrapping key to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array|null>} Resolves to the unwrapped key material
   *   or null if the unwrapping failed because the key did not match.
   */
  async unwrapKey({kekId, wrappedKey, capability, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(wrappedKey, 'wrappedKey', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      '@context': SECURITY_CONTEXT_V2_URL,
      type: 'UnwrapKeyOperation',
      invocationTarget: kekId,
      wrappedKey
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = capability = kekId;
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'unwrapKey'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
      if(response.data.unwrappedKey === null) {
        return null;
      }
      return base64url.decode(response.data.unwrappedKey);
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 404) {
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
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<string>} The base64url-encoded signature.
   */
  async sign({keyId, data, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      '@context': SECURITY_CONTEXT_V2_URL,
      type: 'SignOperation',
      invocationTarget: keyId,
      verifyData: base64url.encode(data)
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = capability = keyId;
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'sign'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
      return response.data.signatureValue;
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 404) {
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
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to verify as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature to
   *   verify.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({keyId, data, signature, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(signature, 'signature', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      '@context': SECURITY_CONTEXT_V2_URL,
      type: 'VerifyOperation',
      invocationTarget: keyId,
      verifyData: base64url.encode(data),
      signatureValue: signature
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = capability = keyId;
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'verify'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
      return response.data.verified;
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 404) {
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
   * @param {object} options - The options to use.
   * @param {string} options.keyId - The ID of the key agreement key to use.
   * @param {object} options.publicKey - The public key to compute the shared
   *   secret against; the public key type must match the key agreement key's
   *   type.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
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
      '@context': SECURITY_CONTEXT_V2_URL,
      type: 'DeriveSecretOperation',
      invocationTarget: keyId,
      publicKey
    };

    let url;
    if(capability) {
      url = KmsClient._getInvocationTarget({capability});
    } else {
      url = capability = keyId;
    }

    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'deriveSecret'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
      return base64url.decode(response.data.secret);
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 404) {
        const err = new Error('Key agreement key not found.');
        err.name = 'NotFoundError';
        throw err;
      }
      throw e;
    }
  }

  /**
   * Stores a delegated authorization capability, enabling it to be invoked by
   * its designated invoker.
   *
   * @param {object} options - The options to use.
   * @param {object} options.capabilityToEnable - The capability to enable.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<object>} Resolves once the operation completes.
   */
  async enableCapability({capabilityToEnable, invocationSigner}) {
    _assert(capabilityToEnable, 'capabilityToEnable', 'object');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const url = `${this.keystore}/authorizations`;
    const capability = `${this.keystore}/zcaps/authorizations`;
    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: capabilityToEnable, capability, invocationSigner,
        capabilityAction: 'write'
      });
      // send request
      const {httpsAgent} = this;
      await axios.post(url, capabilityToEnable, {headers, httpsAgent});
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 409) {
        const err = new Error('Duplicate error.');
        err.name = 'DuplicateError';
        throw err;
      }
      throw e;
    }
  }

  /**
   * Removes a previously stored delegated authorization capability, preventing
   * it from being invoked by its designated invoker.
   *
   * @param {object} options - The options to use.
   * @param {object} options.id - The ID of the capability to revoke.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<boolean>} Resolves to `true` if the document was deleted
   *   and `false` if it did not exist.
   */
  async disableCapability({id, invocationSigner}) {
    _assert(id, 'id', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const url = `${this.keystore}/authorizations?id=${encodeURIComponent(id)}`;
    const capability = `${this.keystore}/zcaps/authorizations`;
    try {
      // sign HTTP header
      const headers = await signCapabilityInvocation({
        url, method: 'delete', headers: DEFAULT_HEADERS,
        capability, invocationSigner,
        // TODO: should `delete` be used here as a separate action?
        capabilityAction: 'write'
      });
      // send request
      const {httpsAgent} = this;
      await axios.delete(url, {headers, httpsAgent});
    } catch(e) {
      const {response = {}} = e;
      if(response.status === 404) {
        return false;
      }
      throw e;
    }
    return true;
  }

  /**
   * Creates a new keystore using the given configuration.
   *
   * @param {object} options - The options to use.
   * @param {string} options.url - The url to post the configuration to.
   * @param {string} options.config - The keystore's configuration.
   * @param {https.Agent} [options.httpsAgent=undefined] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the newly
   *   created keystore.
   */
  static async createKeystore({url = '/kms/keystores', config, httpsAgent}) {
    _assert(url, 'url', 'string');
    _assert(config, 'config', 'object');
    _assert(config.controller, 'config.controller', 'string');
    const response = await axios.post(
      url, config, {headers: DEFAULT_HEADERS, httpsAgent});
    return response.data;
  }

  /**
   * Gets the configuration for a keystore by its ID.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The keystore's ID.
   * @param {https.Agent} [options.httpsAgent=undefined] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the keystore.
   */
  static async getKeystore({id, httpsAgent}) {
    _assert(id, 'id', 'string');
    const response = await axios.get(
      id, {headers: DEFAULT_HEADERS, httpsAgent});
    return response.data;
  }

  /**
   * Finds the configuration for a keystore by its controller and reference ID.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.url] - The url to query.
   * @param {string} options.controller - The keystore's controller.
   * @param {string} options.referenceId - The keystore's reference ID.
   * @param {https.Agent} [options.httpsAgent=undefined] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {Promise<object>} Resolves to the configuration for the keystore.
   */
  static async findKeystore(
    {url = '/kms/keystores', controller, referenceId, httpsAgent}) {
    _assert(controller, 'controller', 'string');
    _assert(referenceId, 'referenceId', 'string');
    const response = await axios.get(url, {
      params: {controller, referenceId},
      headers: DEFAULT_HEADERS,
      httpsAgent
    });
    return response.data[0] || null;
  }

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
