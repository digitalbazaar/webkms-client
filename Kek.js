/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {KmsClient} from './KmsClient.js';

export class Kek {
  /**
   * Creates a new instance of a key encryption key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of this key.
   * @param {Object} options.authenticator - An API for creating digital
   *   signatures using an authentication key for a KMS service.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Kek} The new Kek instance.
   */
  constructor({id, authenticator, kmsClient = new KmsClient()}) {
    this.id = id;
    // TODO: support other algorithms
    this.algorithm = 'A256KW';
    this.authenticator = authenticator;
    this.kmsClient = kmsClient;
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.unwrappedKey - The key material as a
   *   Uint8Array.
   *
   * @returns {Promise<string>} The base64url-encoded wrapped key bytes.
   */
  async wrapKey({unwrappedKey}) {
    const {id: kekId, kmsClient, authenticator} = this;
    return kmsClient.wrapKey({kekId, unwrappedKey, authenticator});
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array>} The key bytes.
   */
  async unwrapKey({wrappedKey}) {
    const {id: kekId, kmsClient, authenticator} = this;
    return kmsClient.unwrapKey({kekId, wrappedKey, authenticator});
  }

  // TODO: remove aliases for wrap and unwrap
  async wrap({key}) {
    return this.wrapKey({unwrappedKey: key});
  }
  async unwrap({wrappedKey}) {
    return this.unwrapKey({wrappedKey});
  }
}
