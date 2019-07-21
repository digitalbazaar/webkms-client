/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {KmsClient} from './KmsClient.js';

export class KeyAgreementKey {
  /**
   * Creates a new instance of a key agreement key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The public key ID to use when expressing
   *   this key publicly; this may be different from the key ID used to
   *   identify the key with the KMS, which case pass `kmsId` as well.
   * @param {string} [options.kmsId=options.id] - The private key ID used to
   *   identify the key with the KMS.
   * @param {Object} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {Object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {KeyAgreementKey} The new AsymmetricKey instance.
   */
  constructor({
    id, kmsId = id, type, capability, invocationSigner,
    kmsClient = new KmsClient()
  }) {
    this.id = id;
    this.kmsId = kmsId;
    this.type = type;
    this.capability = capability;
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
  }

  /**
  * Derives a shared secret via the given peer public key, typically for use
  * as one parameter for computing a shared key. It should not be used as
  * a shared key itself, but rather input into a key derivation function (KDF)
  * to produce a shared key.
   *
   * @param {Object} options - The options to use.
   * @param {Object} options.publicKey - The public key to compute the shared
   *   secret against; the public key type must match this KeyAgreementKey's
   *   type.
   *
   * @returns {Promise<Uint8Array>} The shared secret bytes.
   */
  async deriveSecret({publicKey}) {
    if(!publicKey || typeof publicKey !== 'object') {
      throw new TypeError('"publicKey" must be an object.');
    }
    if(publicKey.type !== this.type) {
      throw Error(
        `The given public key type "${publicKey.type}" does not match this ` +
        `key agreement key's ${this.type}.`);
    }
    const {kmsId: keyId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.deriveSecret(
      {keyId, publicKey, capability, invocationSigner});
  }
}
