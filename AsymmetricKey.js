/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import {KmsClient} from './KmsClient.js';

export class AsymmetricKey {
  /**
   * Creates a new instance of an asymmetric key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The public key ID to use when signing
   *   with this key; this may be different from the key ID used to
   *   identify the key with the KMS.
   * @param {Object} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {Object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {AsymmetricKey} The new AsymmetricKey instance.
   */
  constructor({
    id, type, capability, invocationSigner,
    kmsClient = new KmsClient()
  }) {
    this.id = id;
    this.type = type;
    this.capability = capability && capability.id;
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   *
   * @returns {Promise<Uint8Array>} The signature.
   */
  async sign({data}) {
    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    const signatureValue = await kmsClient.sign(
      {keyId, data, capability, invocationSigner});
    return base64url.decode(signatureValue);
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature to
   *   verify.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({data, signature}) {
    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.verify(
      {keyId, data, signature, capability, invocationSigner});
  }
}
