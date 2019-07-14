/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import base64url from 'base64url-universal';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';

const DEFAULT_HEADERS = {Accept: 'application/ld+json, application/json'};

export class KmsClient {
  /**
   * Creates a new KmsClient.
   *
   * @param {Object} options - The options to use.
   * @param {https.Agent} [options.httpsAgent=undefined] - An optional
   *   node.js `https.Agent` instance to use when making requests.
   *
   * @returns {KmsClient} The new instance.
   */
  constructor({httpsAgent} = {}) {
    this.httpsAgent = httpsAgent;
  }

  /**
   * Generates a new cryptographic key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.keyId - The ID of the new key.
   * @param {string} options.kmsModule - The KMS module to use.
   * @param {string} options.type - The key type (e.g. 'AesKeyWrappingKey2019').
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Object>} The key description for the key.
   */
  async generateKey({keyId, kmsModule, type, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(kmsModule, 'kmsModule', 'string');
    _assert(type, 'type', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      type: 'GenerateKeyOperation',
      invocationTarget: {id: keyId, type, controller: invocationSigner.id},
      kmsModule
    };

    try {
      // sign HTTP header
      const url = keyId;
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
   * @param {Object} options - The options to use.
   * @param {string} options.keyId - The ID of the key.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Object>} The key description.
   */
  async getKeyDescription({keyId, capability, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const url = keyId;
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
   * @param {Object} options - The options to use.
   * @param {string} options.kekId - The ID of the wrapping key to use.
   * @param {Uint8Array} options.unwrappedKey - The unwrapped key material as
   *   a Uint8Array.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<string>} The base64url-encoded wrapped key bytes.
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
    try {
      // sign HTTP header
      const url = kekId;
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
   * @param {Object} options - The options to use.
   * @param {string} options.kekId - The ID of the unwrapping key to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The unwrapped key material.
   */
  async unwrapKey({kekId, wrappedKey, capability, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(wrappedKey, 'wrappedKey', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');

    const operation = {
      type: 'UnwrapKeyOperation',
      invocationTarget: kekId,
      wrappedKey
    };
    try {
      // sign HTTP header
      const url = kekId;
      const headers = await signCapabilityInvocation({
        url, method: 'post', headers: DEFAULT_HEADERS,
        json: operation, capability, invocationSigner,
        capabilityAction: 'unwrapKey'
      });
      // send request
      const {httpsAgent} = this;
      const response = await axios.post(url, operation, {headers, httpsAgent});
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
   * @param {Object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   *
   * @returns {Promise<string>} The base64url-encoded signature.
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
    try {
      // sign HTTP header
      const url = keyId;
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
   * @param {Object} options - The options to use.
   * @param {string} options.keyId - The ID of the signing key to use.
   * @param {Uint8Array} options.data - The data to verify as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature to
   *   verify.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
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
      type: 'VerifyOperation',
      invocationTarget: keyId,
      verifyData: base64url.encode(data),
      signatureValue: signature
    };
    try {
      // sign HTTP header
      const url = keyId;
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
   * @param {Object} options - The options to use.
   * @param {string} options.keyId - The ID of the key agreement key to use.
   * @param {Object} options.publicKey - The public key to compute the shared
   *   secret against; the public key type must match the key agreement key's
   *   type.
   * @param {string} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {Object} options.invocationSigner - An API with an
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
    try {
      // sign HTTP header
      const url = keyId;
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
