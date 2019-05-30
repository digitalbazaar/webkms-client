/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import cryptoLd from 'crypto-ld';

const {Ed25519KeyPair} = cryptoLd;

export class Ed25519Key {
  /**
   * Creates a new instance of an Ed25519.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of this key.
   * @param {Object} options.keyDescription - A key description object,
   *   specific to the key type.
   * @param {Object} options.invocationSigner - An API for signing
   *   authorization capability invocations for a KMS service.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Ed25519} The new Ed25519 instance.
   */
  constructor({id, keyDescription, invocationSigner, kmsClient}) {
    // `id` contains the public id exposed by the publicNode API
    this.id = id || '';
    this.type = 'Ed25519VerificationKey2018';
    const {privateKey = id, publicKeyBase58} = keyDescription;
    // this is the private key ID only, not key material
    this.privateKey = privateKey;
    this.publicKeyBase58 = publicKeyBase58;
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
  }

  // FIXME: experimental, do not use
  _export() {
    return {
      id: this.id,
      type: this.type,
      privateKey: this.privateKey,
      publicKeyBase58: this.publicKeyBase58
    };
  }

  /**
   * Generates and returns a multiformats encoded
   * ed25519 public key fingerprint (for use with cryptonyms, for example).
   *
   * @see https://github.com/multiformats/multicodec
   *
   * @returns {string} The fingerprint.
   */
  fingerprint() {
    const {publicKeyBase58} = this;
    return Ed25519KeyPair.fingerprintFromPublicKey({publicKeyBase58});
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
    const {privateKey: keyId, kmsClient, invocationSigner} = this;
    const signatureValue = await kmsClient.sign(
      {keyId, data, invocationSigner});
    return base64url.decode(signatureValue);
  }
}
