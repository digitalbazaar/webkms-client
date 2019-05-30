/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import axios from 'axios';
import base64url from 'base64url-universal';
import jsigs from 'jsonld-signatures';
import {CapabilityInvocation} from 'ocapld';

const {SECURITY_CONTEXT_V2_URL, sign, suites} = jsigs;
const {Ed25519Signature2018} = suites;

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
   * @param {String} [options.capability=options.keyId] - The ID of
   *   the OCAP-LD authorization capability to use to authorize the invocation
   *   of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property, a `type` property, and a `sign` function for signing
   *   a capability invocation.
   *
   * @returns {Promise<Object>} The key description for the key, including,
   *   at a minimum, its `id`.
   */
  async generateKey(
    {keyId, kmsModule, type, capability = keyId, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(kmsModule, 'kmsModule', 'string');
    _assert(type, 'type', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');
    return _postOperation({
      url: keyId,
      operation: {
        type: 'GenerateKeyOperation',
        invocationTarget: {id: keyId, type, controller: invocationSigner.id},
        kmsModule
      },
      capability,
      invocationSigner,
      httpsAgent: this.httpsAgent
    });
  }

  /**
   * Gets the key description for the given key ID.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.keyId - The ID of the key.
   *
   * @returns {Promise<Object>} The key description.
   */
  async getKeyDescription({keyId}) {
    const response = await axios({
      url: keyId,
      method: 'GET',
      httpsAgent: this.httpsAgent
    });
    return response.data;
  }

  /**
   * Wraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {Object} options - The options to use.
   * @param {string} options.kekId - The ID of the wrapping key to use.
   * @param {Uint8Array} options.unwrappedKey - The unwrapped key material as
   *   a Uint8Array.
   * @param {String} [options.capability=options.kekId] - The ID of
   *   the OCAP-LD authorization capability to use to authorize the invocation
   *   of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property, a `type` property, and a `sign` function for signing
   *   a capability invocation.
   *
   * @returns {Promise<string>} The base64url-encoded wrapped key bytes.
   */
  async wrapKey({kekId, unwrappedKey, capability = kekId, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(unwrappedKey, 'unwrappedKey', 'Uint8Array');
    _assert(invocationSigner, 'invocationSigner', 'object');
    const {wrappedKey} = await _postOperation({
      url: kekId,
      operation: {
        type: 'WrapKeyOperation',
        invocationTarget: kekId,
        unwrappedKey: base64url.encode(unwrappedKey)
      },
      capability,
      invocationSigner,
      httpsAgent: this.httpsAgent
    });
    return wrappedKey;
  }

  /**
   * Unwraps a cryptographic key using a key encryption key (KEK).
   *
   * @param {Object} options - The options to use.
   * @param {string} options.kekId - The ID of the unwrapping key to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   * @param {String} [options.capability=options.kekId] - The ID of
   *   the OCAP-LD authorization capability to use to authorize the invocation
   *   of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property, a `type` property, and a `sign` function for signing
   *   a capability invocation.
   *
   * @returns {Promise<Uint8Array>} The unwrapped key material.
   */
  async unwrapKey({kekId, wrappedKey, capability = kekId, invocationSigner}) {
    _assert(kekId, 'kekId', 'string');
    _assert(wrappedKey, 'wrappedKey', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');
    const {unwrappedKey} = await _postOperation({
      url: kekId,
      operation: {
        type: 'UnwrapKeyOperation',
        invocationTarget: kekId,
        wrappedKey
      },
      capability,
      invocationSigner,
      httpsAgent: this.httpsAgent
    });
    return base64url.decode(unwrappedKey);
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
   * @param {String} [options.capability=options.keyId] - The ID of
   *   the OCAP-LD authorization capability to use to authorize the invocation
   *   of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property, a `type` property, and a `sign` function for signing
   *   a capability invocation.
   *
   * @returns {Promise<string>} The base64url-encoded signature.
   */
  async sign({keyId, data, capability = keyId, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(invocationSigner, 'invocationSigner', 'object');
    const {signatureValue} = await _postOperation({
      url: keyId,
      operation: {
        type: 'SignOperation',
        invocationTarget: keyId,
        verifyData: base64url.encode(data)
      },
      capability,
      invocationSigner,
      httpsAgent: this.httpsAgent
    });
    return signatureValue;
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
   * @param {String} [options.capability=options.keyId] - The ID of
   *   the OCAP-LD authorization capability to use to authorize the invocation
   *   of this operation.
   * @param {Object} options.invocationSigner - An API with an
   *   `id` property, a `type` property, and a `sign` function for signing
   *   a capability invocation.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({keyId, data, signature, capability = keyId, invocationSigner}) {
    _assert(keyId, 'keyId', 'string');
    _assert(data, 'data', 'Uint8Array');
    _assert(signature, 'signature', 'string');
    _assert(invocationSigner, 'invocationSigner', 'object');
    const {verified} = await _postOperation({
      url: keyId,
      operation: {
        type: 'VerifyOperation',
        invocationTarget: keyId,
        verifyData: base64url.encode(data),
        signatureValue: signature
      },
      capability,
      invocationSigner,
      httpsAgent: this.httpsAgent
    });
    return verified;
  }
}

/**
 * Posts an operation to the KMS service.
 *
 * @param {Object} options - The options to use.
 * @param {string} options.url - The URL to post to, such as a key identifier.
 * @param {Object} options.operation - The operation to run.
 * @param {String} [options.capability=options.url] - The ID of the OCAP-LD
 *   authorization capability to use to authorize the invocation of the
 *   operation.
 * @param {Object} options.invocationSigner - An API with an `id` property, a
 *   `type` property, and a `sign` function for digitally signing capability
 *   invocations.
 * @param {https.Agent} [options.httpsAgent=undefined] - An optional
 *   node.js `https.Agent` instance to use when making requests.
 *
 * @returns {Promise<Object>} Resolves to the result of the operation.
 */
async function _postOperation(
  {url, operation, capability = url, invocationSigner, httpsAgent}) {
  // attach capability invocation to operation
  operation = {'@context': SECURITY_CONTEXT_V2_URL, ...operation};
  const signer = invocationSigner;
  const data = await sign(operation, {
    // TODO: map `invocationSigner.type` to signature suite
    suite: new Ed25519Signature2018({
      signer,
      verificationMethod: signer.id
    }),
    purpose: new CapabilityInvocation({capability})
  });

  // send operation
  const response = await axios({
    url,
    method: 'POST',
    data,
    httpsAgent
  });
  return response.data;
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
