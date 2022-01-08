/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {KmsClient} from './KmsClient.js';

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

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
   * @param {object} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of KmsClient methods.
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
    this.capability = capability;
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
    this._keyDescription = keyDescription;

    // set key information from capability as needed
    if(capability) {
      let invocationTarget;
      if(typeof capability === 'string') {
        if(!capability.startsWith(ZCAP_ROOT_PREFIX)) {
          throw new Error(
            'If "capability" is a string, it must be a root capability.');
        }
        invocationTarget = decodeURIComponent(
          capability.substring(ZCAP_ROOT_PREFIX.length));
      } else {
        ({invocationTarget} = capability);
      }
      if(!this.id) {
        this.id = invocationTarget.publicAlias || invocationTarget.id ||
          invocationTarget;
      }
      if(!this.kmsId) {
        this.kmsId = invocationTarget.id || invocationTarget;
      }
      if(!this.type) {
        this.type = invocationTarget.type;
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

  // FIXME: add `fromCapability()`
  // ... use capability to getKeyDescription() and return instance from that
}
