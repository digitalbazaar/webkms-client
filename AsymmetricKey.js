/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {KmsClient} from './KmsClient.js';

export class AsymmetricKey {
  /**
   * Creates a new instance of an asymmetric key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The public key ID to use when expressing
   *   this key publicly (i.e., as a verification method); this may be
   *   different from the key ID used to identify the key with the KMS, which
   *   case pass `kmsId` as well.
   * @param {string} [options.kmsId=options.id] - The private key ID used to
   *   identify the key with the KMS.
   * @param {object} [options.capability] - Do not pass "capability" here;
   *   use `.fromCapability` instead.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   * @param {object} [options.keyDescription] - An optional `keyDescription` to
   *   cache.
   * @param {string} [options.type] - A type for the key instance.
   *
   * @returns {AsymmetricKey} The new AsymmetricKey instance.
   */
  constructor({
    id, kmsId = id, type, capability, invocationSigner,
    kmsClient = new KmsClient(), keyDescription
  }) {
    if(capability) {
      throw new Error(
        '"capability" parameter not allowed in constructor; ' +
        'use ".fromCapability" instead.');
    }
    this.id = id;
    this.kmsId = kmsId;
    this.type = type;
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
    this._keyDescription = keyDescription;
    if(keyDescription) {
      if(id === undefined) {
        this.id = keyDescription.id;
      }
      if(type === undefined) {
        this.type = keyDescription.type;
      }
    }
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   *
   * @returns {Promise<Uint8Array>} The signature.
   */
  async sign({data}) {
    const {kmsId: keyId, kmsClient, capability, invocationSigner} = this;
    const signatureValue = await kmsClient.sign(
      {keyId, data, capability, invocationSigner});
    return signatureValue;
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature to
   *   verify.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({data, signature}) {
    const {kmsId: keyId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.verify(
      {keyId, data, signature, capability, invocationSigner});
  }

  /**
   * Gets the key description for this key.
   *
   * @param {object} options - The options to use.
   *
   * @returns {Promise<object>} The key description.
   */
  async getKeyDescription({} = {}) {
    if(!this._keyDescription) {
      const {kmsId: keyId, kmsClient, capability, invocationSigner} = this;
      this._keyDescription = await kmsClient.getKeyDescription(
        {keyId, capability, invocationSigner});
    }
    // return clone of cached description
    return JSON.parse(JSON.stringify(this._keyDescription));
  }

  /**
   * Creates a new instance of an asymmetric key from an authorization
   * capability.
   *
   * @param {object} options - The options to use.
   * @param {object} [options.capability] - The ZCAP-LD authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {AsymmetricKey} The new AsymmetricKey instance.
   */
  static async fromCapability({capability, invocationSigner, kmsClient}) {
    // get key description via capability
    const keyDescription = await kmsClient.getKeyDescription(
      {capability, invocationSigner});

    // build asymmetric key from description
    const kmsId = KmsClient._getInvocationTarget({capability});
    const key = new AsymmetricKey({
      kmsId, keyDescription, kmsClient, invocationSigner
    });
    key.capability = capability;
    return key;
  }
}
