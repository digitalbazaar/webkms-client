/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import LRU from 'lru-cache';
import {KmsClient} from './KmsClient.js';

const MAX_CACHE_AGE = 3000;
const MAX_CACHE_SIZE = 100;
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
   * @see https://tools.ietf.org/html/rfc2104
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
    this.cache = new LRU({max: MAX_CACHE_SIZE, maxAge: MAX_CACHE_AGE});
    this._pruneCacheTimer = null;
  }

  /**
   * Signs some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {boolean} [options.useCache=true] - Enable the use of a cache.
   *
   * @returns {Promise<string>} The base64url-encoded signature.
   */
  async sign({data, useCache = true}) {
    const cacheKey = `sign-${base64url.encode(data)}`;
    if(useCache) {
      const signature = this.cache.get(cacheKey);
      if(signature) {
        return signature;
      }
    }

    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    const promise = kmsClient.sign({keyId, data, capability, invocationSigner});

    if(useCache) {
      // 1. Set promise in cache
      this.cache.set(cacheKey, promise);

      // 2. Schedule cache pruning if not already scheduled
      if(!this._pruneCacheTimer) {
        this._pruneCacheTimer = setTimeout(
          () => this._pruneCache(), MAX_CACHE_AGE);
      }
    }

    try {
      const signature = await promise;
      return signature;
    } catch(e) {
      if(useCache) {
        this.cache.del(cacheKey);
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
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {string} options.signature - The base64url-encoded signature
   *   to verify.
   * @param {boolean} [options.useCache=true] - Enable the use of a cache.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({data, signature, useCache = true}) {
    const cacheKey = `verify-${base64url.encode(data)}`;
    if(useCache) {
      const verified = this.cache.get(cacheKey);
      if(verified !== undefined) {
        return verified;
      }
    }

    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    const promise = kmsClient.verify(
      {keyId, data, signature, capability, invocationSigner});

    if(useCache) {
      // 1. Set promise in cache
      this.cache.set(cacheKey, promise);

      // 2. Schedule cache pruning if not already scheduled
      if(!this._pruneCacheTimer) {
        this._pruneCacheTimer = setTimeout(
          () => this._pruneCache(), MAX_CACHE_AGE);
      }
    }

    try {
      const verified = await promise;
      return verified;
    } catch(e) {
      if(useCache) {
        this.cache.del(cacheKey);
      }
      throw e;
    }
  }

  _pruneCache() {
    this.cache.prune();
    if(this.cache.length === 0) {
      // cache is empty, do not schedule pruning
      this._pruneCacheTimer = null;
    } else {
      // schedule another run
      this._pruneCacheTimer = setTimeout(() =>
        this._pruneCache(), MAX_CACHE_AGE);
    }
  }
}
