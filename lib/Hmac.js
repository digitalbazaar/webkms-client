/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {KmsClient} from './KmsClient.js';
import {LruCache} from '@digitalbazaar/lru-memoize';

const CACHE_MAX = 100;
const CACHE_TTL = 3000;
const JOSE_ALGORITHM_MAP = {
  Sha256HmacKey2019: 'HS256'
};

export class Hmac {
  /**
   * Creates a new instance of an HMAC.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID for the hmac key.
   * @param {string} [options.kmsId=options.id] - The key ID used to
   *   identify the key with the KMS.
   * @param {string} options.type - The type for the hmac.
   * @param {object} [options.capability] - Do not pass "capability" here;
   *   use `.fromCapability` instead.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Hmac} The new Hmac instance.
   * @see https://tools.ietf.org/html/rfc2104
   */
  constructor({
    id, kmsId = id, type, capability, invocationSigner,
    kmsClient = new KmsClient()
  }) {
    if(capability) {
      throw new Error(
        '"capability" parameter not allowed in constructor; ' +
        'use ".fromCapability" instead.');
    }
    this.id = id;
    this.kmsId = kmsId;
    this.type = type;
    this.algorithm = JOSE_ALGORITHM_MAP[type];
    if(!this.algorithm) {
      throw new Error(`Unknown key type "${this.type}".`);
    }
    this.invocationSigner = invocationSigner;
    this.kmsClient = kmsClient;
    this.capability = undefined;
    this._cache = new LruCache({
      max: CACHE_MAX,
      ttl: CACHE_TTL,
      updateAgeOnGet: true
    });
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
   * @returns {Promise<Uint8Array>} The signature.
   */
  async sign({data, useCache = true}) {
    if(!useCache) {
      return this._uncachedSign({data, useCache});
    }

    return this._cache.memoize({
      key: `sign-${base64url.encode(data)}`,
      fn: () => this._uncachedSign({data, useCache})
    });
  }

  /**
   * Verifies some data. Note that the data will be sent to the server, so if
   * this data is intended to be secret it should be hashed first. However,
   * hashing the data first may present interoperability issues so choose
   * wisely.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign as a Uint8Array.
   * @param {Uint8Array|string} options.signature - The Uint8Array or
   *   base64url-encoded signature to verify.
   * @param {boolean} [options.useCache=true] - Enable the use of a cache.
   *
   * @returns {Promise<boolean>} `true` if verified, `false` if not.
   */
  async verify({data, signature, useCache = true}) {
    if(!useCache) {
      return this._uncachedVerify({data, signature, useCache});
    }

    return this._cache.memoize({
      key: `verify-${base64url.encode(data)}`,
      fn: () => this._uncachedVerify({data, signature, useCache})
    });
  }

  /**
   * Creates a new instance of an hmac key from an authorization capability.
   *
   * @param {object} options - The options to use.
   * @param {object} [options.capability] - The authorization
   *   capability to use to authorize the invocation of KmsClient methods.
   * @param {object} options.invocationSigner - An API for signing
   *   a capability invocation.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Hmac} The new Hmac instance.
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
    const key = new Hmac({id, type, kmsClient, invocationSigner});
    key.capability = capability;
    return key;
  }

  _pruneCache() {
    this._cache.cache.purgeStale();
    if(this._cache.cache.length === 0) {
      // cache is empty, do not schedule pruning
      this._pruneCacheTimer = null;
    } else {
      // schedule another run
      this._schedulePruning();
    }
  }

  _schedulePruning() {
    this._pruneCacheTimer = setTimeout(() => this._pruneCache(), CACHE_TTL);
  }

  async _uncachedSign({data, useCache}) {
    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    const promise = kmsClient.sign({keyId, data, capability, invocationSigner});

    // schedule cache pruning if not already scheduled
    if(useCache && !this._pruneCacheTimer) {
      this._schedulePruning();
    }

    return promise;
  }

  async _uncachedVerify({data, signature, useCache}) {
    const {id: keyId, kmsClient, capability, invocationSigner} = this;
    const promise = kmsClient.verify(
      {keyId, data, signature, capability, invocationSigner});

    // schedule cache pruning if not already scheduled
    if(useCache && !this._pruneCacheTimer) {
      this._schedulePruning();
    }

    return promise;
  }
}
