/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import crypto from './crypto.js';
import cryptoLd from 'crypto-ld';
const {Ed25519KeyPair} = cryptoLd;
import {Ed25519Key} from './Ed25519Key.js';
import {Kek} from './Kek.js';
import {Hmac} from './Hmac.js';
import {SeedCache} from './SeedCache.js';
import {KmsClient} from './KmsClient.js';
import {TextDecoder, TextEncoder} from './util.js';

const VERSIONS = ['recommended', 'fips'];
const _seedCache = new SeedCache();

export class ControllerKey {
  /**
   * Creates a new instance of a ControllerKey. This function should never
   * be called directly. Use one of these methods to create a ControllerKey
   * instance.
   *
   * A ControllerKey can be passed as an `authenticator` to a KmsClient, but
   * a KmsClient instance is typically used internally by other instances that
   * can be created via the ControllerKey API such as instances of the Kek
   * and Hmac classes.
   *
   * @example
   * ControllerKey.fromSecret();
   * ControllerKey.fromCache();
   * ControllerKey.fromBiometric();
   * ControllerKey.fromFido();
   *
   * @param {Object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create the key.
   * @param {Object} options.key - An API with an `id` property, a
   *   `type` property, and a `sign` function for authentication purposes.
   * @param {Object} options.signer - An API for creating digital signatures
   *   using the key.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {ControllerKey} the new instance.
   */
  constructor({handle, key, kmsClient = new KmsClient()}) {
    this.handle = handle;
    this.id = key.id;
    this.type = key.type;
    this._key = key;
    this.kmsClient = kmsClient;
  }

  /**
   * Digitally signs the given data.
   *
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.data - The data to sign.
   *
   * @returns {Promise<Uint8Array>} resolves to the signature.
   */
  async sign({data}) {
    return this._key.sign({data});
  }

  /**
   * Generates a key. The key can be a key encryption key (KEK) or an HMAC
   * key. It can be generated using a FIPS-compliant algorithm or the latest
   * recommended algorithm.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the new key.
   * @param {string} options.type - The type of key to create (`hmac` or `kek`).
   * @param {string} options.kmsModule - The name of the KMS module to use to
   *   generate the key.
   * @param {string} [options.version=recommended] - `fips` to
   *   use FIPS-compliant ciphers, `recommended` to use the latest recommended
   *   ciphers.
   *
   * @returns {Promise<Object>} A Kek or Hmac instance.
   */
  async generateKey({id, type, kmsModule, version = 'recommended'}) {
    _assertVersion(version);

    // for the time being, fips and recommended are the same; there is no
    // other standardized key wrapping algorithm
    let Class;
    if(type === 'hmac') {
      type = 'Sha256HmacKey2019';
      Class = Hmac;
    } else if(type === 'kek') {
      type = 'AesKeyWrappingKey2019';
      Class = Kek;
    } else if(type === 'Ed25519VerificationKey2018') {
      type = 'Ed25519VerificationKey2018';
      Class = Ed25519Key;
    } else {
      throw new Error(`Unknown key type "${type}".`);
    }

    const {kmsClient} = this;
    const authenticator = this;
    const keyDescription = await kmsClient.generateKey(
      {keyId: id, kmsModule, type, authenticator});
    const {id: newId} = keyDescription;
    return new Class({id: newId, keyDescription, authenticator, kmsClient});
  }

  /**
   * Gets a KEK API for wrapping and unwrapping cryptographic keys. The key ID
   * is presumed to be associated with the KMS service assigned to this
   * instance.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the KEK.
   *
   * @returns {Promise<Object>} The new Kek instance.
   */
  async getKek({id}) {
    const {kmsClient} = this;
    const authenticator = this;
    // FIXME: call kmsClient.getKeyDescription()? ...to get key algorithm?
    return new Kek({id, authenticator, kmsClient});
  }

  /**
   * Gets an HMAC API for signing and verifying cryptographic keys. The key ID
   * is presumed to be associated with the KMS service assigned to this
   * instance.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the HMAC key.
   *
   * @returns {Promise<Object>} The new Hmac instance.
   */
  async getHmac({id}) {
    const {kmsClient} = this;
    const authenticator = this;
    // FIXME: call kmsClient.getKeyDescription()? ...to get key algorithm?
    return new Hmac({id, authenticator, kmsClient});
  }

  /**
   * Deterministically generates a key from a secret and a handle.
   *
   * @param {Object} options - The options to use.
   * @param {string|Uint8Array} [options.secret] - A secret to use as input
   *   when generating the key, e.g., a bcrypt hash of a password.
   * @param {string} options.handle - A semantic identifier that is mixed
   *   with the secret like a salt and, if `cache` is true, will be used to
   *   identify the key in the cache. A common use for this field is to use
   *   the account ID for a user in a system.
   * @param {boolean} [options.cache=true] - Use `true` to cache the key,
   *   `false` not to; a cached key must be cleared via `clearCache` or it will
   *   persist until the user clears their local website storage.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Promise<ControllerKey>} The new ControllerKey instance.
   */
  static async fromSecret(
    {secret, handle, cache = true, kmsClient = new KmsClient()}) {
    if(typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.');
    }
    if(typeof secret === 'string') {
      secret = _stringToUint8Array(secret);
    } else if(!(secret instanceof Uint8Array)) {
      throw new TypeError('"secret" must be a Uint8Array or a string.');
    }

    // compute salted SHA-256 hash as the seed for the key
    const seed = await _computeSaltedHash({secret, salt: handle});
    const key = await _keyFromSeed({seed});

    // cache seed if requested
    if(cache) {
      await _seedCache.set(handle, seed);
    }

    return new ControllerKey({handle, key, kmsClient});
  }

  static async fromBiometric() {
    throw new Error('Not implemented.');
  }

  static async fromFido() {
    throw new Error('Not implemented.');
  }

  /**
   * Loads a key from a local cache if available. This method will only work if
   * the key for the given account has been previously cached. To clear this
   * key to prevent future loading, call `clearCache` with the key's `handle`.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create the key and differentiate it in the cache.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Promise<ControllerKey>} The new ControllerKey instance
   *   or `null` if no cached key for `handle` could be loaded.
   */
  static async fromCache({handle, kmsClient = new KmsClient()}) {
    if(typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.');
    }
    const seed = await _seedCache.get(handle);
    if(!seed) {
      return null;
    }
    const key = await _keyFromSeed({seed});
    return new ControllerKey({handle, key, kmsClient});
  }

  /**
   * Clears a key from any caches. This must be called for keys created
   * via `fromSecret` with `cache` set to `true` in order to ensure the key
   * cannot be loaded via `fromCache`.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create the key and differentiate it in the cache.
   *
   * @returns {Promise<undefined>} On completion.
   */
  static async clearCache({handle}) {
    await _seedCache.delete(handle);
  }
}

function _stringToUint8Array(data) {
  if(typeof data === 'string') {
    // convert data to Uint8Array
    return new TextEncoder().encode(data);
  }
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a string or Uint8Array.');
  }
  return data;
}

function _uint8ArrayToString(data) {
  if(typeof data === 'string') {
    // already a string
    return data;
  }
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a string or Uint8Array.');
  }
  // convert Uint8Array to string
  return new TextDecoder().decode(data);
}

function _assertVersion(version) {
  if(typeof version !== 'string') {
    throw new TypeError('"version" must be a string.');
  }
  if(!VERSIONS.includes(version)) {
    throw new Error(`Unsupported version "${version}"`);
  }
}

async function _computeSaltedHash({secret, salt}) {
  // compute salted SHA-256 hash
  salt = _uint8ArrayToString(salt);
  secret = _uint8ArrayToString(secret);
  const toHash = _stringToUint8Array(
    `${encodeURIComponent(salt)}:${encodeURIComponent(secret)}`);
  const algorithm = {name: 'SHA-256'};
  return new Uint8Array(await crypto.subtle.digest(algorithm, toHash));
}

async function _keyFromSeed({seed}) {
  // generate Ed25519 key from seed
  const keyPair = await Ed25519KeyPair.generate({seed});

  // create key and specify ID for key using fingerprint
  const key = keyPair.signer();
  key.id = `did:key:${keyPair.fingerprint()}`;
  key.type = keyPair.type;
  return key;
}
