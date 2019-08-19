/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {KmsClient} from './KmsClient.js';

const JOSE_ALGORITHM_MAP = {
  Sha256HmacKey2019: 'HS256'
};

export class Hmac {
  /**
   * Creates a new instance of an HMAC.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID for the hmac key.
   * @param {string} options.type - The type for the hmac.
   * @param {object} [options.capability=undefined] - The OCAP-LD authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Hmac} The new Hmac instance.
   */
  constructor({
    id, type, capability, invocationSigner,
    kmsClient = new KmsClient()
  }) {
    this.id = id;
    this.type = type;
    this.algorithm = JOSE_ALGORITHM_MAP[type];
    if(!this.algorithm) {
      throw new Error(`Unknown key type "${this.type}".`);
    }
    this.capability = capability;
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
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
   * @returns {Promise<string>} The base64url-encoded signature.
   */
  async sign({data}) {
    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.sign({keyId, data, capability, invocationSigner});
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature
   *   to verify.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({data, signature}) {
    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    return kmsClient.verify(
      {keyId, data, signature, capability, invocationSigner});
  }
}
