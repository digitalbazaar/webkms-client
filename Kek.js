/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {KmsClient} from './KmsClient.js';

const JOSE_ALGORITHM_MAP = {
  AesKeyWrappingKey2019: 'A256KW'
};

export class Kek {
  /**
   * Creates a new instance of a key encryption key.
   * Used to protect the content encryption key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID for this key.
   * @param {string} options.type - The type for this key.
   * @param {object} [options.capability] - Do not pass "capability" here;
   *   use `.fromCapability` instead.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Kek} The new Kek instance.
   */
  constructor({
    id, type, capability, invocationSigner,
    kmsClient = new KmsClient()
  }) {
    if(capability) {
      throw new Error(
        '"capability" parameter not allowed in constructor; ' +
        'use ".fromCapability" instead.');
    }
    this.id = id;
    this.type = type;
    this.algorithm = JOSE_ALGORITHM_MAP[type];
    if(!this.algorithm) {
      throw new Error(`Unknown key type "${this.type}".`);
    }
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
    this.capability = undefined;
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.unwrappedKey - The key material
   *   as a Uint8Array.
   *
   * @returns {Promise<Uint8Array>} The wrapped key bytes.
   */
  async wrapKey({unwrappedKey}) {
    const {id: kekId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.wrapKey(
      {kekId, unwrappedKey, capability, invocationSigner});
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array|null>} Resolves to the key bytes or null if
   *   the unwrapping fails because the key does not match.
   */
  async unwrapKey({wrappedKey}) {
    const {id: kekId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.unwrapKey(
      {kekId, wrappedKey, capability, invocationSigner});
  }

  /**
   * Creates a new instance of a key encryption key from an authorization
   * capability.
   *
   * @param {object} options - The options to use.
   * @param {object} [options.capability] - The authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Kek} The new Kek instance.
   */
  static async fromCapability({
    capability, invocationSigner, kmsClient = new KmsClient()
  }) {
    // get key description via capability
    const keyDescription = await kmsClient.getKeyDescription(
      {capability, invocationSigner});

    // build asymmetric key from description
    const id = KmsClient._getInvocationTarget({capability});
    const {type} = keyDescription;
    const key = new Kek({id, type, kmsClient, invocationSigner});
    key.capability = capability;
    return key;
  }

}
