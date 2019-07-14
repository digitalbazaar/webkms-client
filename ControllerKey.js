/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import crypto from './crypto.js';
import cryptoLd from 'crypto-ld';
const {Ed25519KeyPair} = cryptoLd;
import {AsymmetricKey} from './AsymmetricKey.js';
import {Kek} from './Kek.js';
import {KeyAgreementKey} from './KeyAgreementKey.js';
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
   * A ControllerKey can be passed as an `invocationSigner` to a KmsClient, but
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
      Class = AsymmetricKey;
    } else if(type === 'X25519KeyAgreementKey2019') {
      type = 'X25519KeyAgreementKey2019';
      Class = KeyAgreementKey;
    } else {
      throw new Error(`Unknown key type "${type}".`);
    }

    const {kmsClient} = this;
    const invocationSigner = this;
    const keyDescription = await kmsClient.generateKey(
      {keyId: id, kmsModule, type, invocationSigner});
    const {id: newId} = keyDescription;
    return new Class({id: newId, type, invocationSigner, kmsClient});
  }

  /**
   * Gets a KEK API for wrapping and unwrapping cryptographic keys. The API
   * will use this ControllerKey instance to sign capability invocations to
   * wrap or unwrap keys.
   *
   * If this ControllerKey is a controller of the KEK, then the API for it can
   * returned by passing only the key description. Otherwise, an OCAP-LD
   * authorization capability must also be passed; without this capability,
   * calls to the returned API will not be authorized to perform KEK operations.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {string} options.type - The type of key
   *   (e.g. `AesKeyWrappingKey2019`).
   * @param {string} [options.capability=undefined] - The ID of the OCAP-LD
   *   authorization capability to use to authorize the invocation of the
   *   operations.
   *
   * @returns {Promise<Object>} The new Kek instance.
   */
  async getKek({id, type, capability}) {
    const {kmsClient} = this;
    const invocationSigner = this;
    return new Kek({id, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Gets an HMAC API for signing and verifying data. The API
   * will use this ControllerKey instance to sign capability invocations to
   * sign or verify data.
   *
   * If this ControllerKey is a controller of the HMAC, then the API for it can
   * returned by passing only the key description. Otherwise, an OCAP-LD
   * authorization capability must also be passed; without this capability,
   * calls to the returned API will not be authorized to perform HMAC
   * operations.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {string} options.type - The type of key (e.g. `Sha256HmacKey2019`).
   * @param {string} [options.capability=undefined] - The ID of the OCAP-LD
   *   authorization capability to use to authorize the invocation of the
   *   operations.
   *
   * @returns {Promise<Object>} The new Hmac instance.
   */
  async getHmac({id, type, capability}) {
    const {kmsClient} = this;
    const invocationSigner = this;
    return new Hmac({id, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Gets an AsymmetricKey API for signing and verifying data. The API
   * will use this ControllerKey instance to sign capability invocations to
   * sign or verify data.
   *
   * If this ControllerKey is a controller of the AsymmetricKey, then the API
   * for it can returned by passing only the key description. Otherwise, an
   * authorization capability must also be passed; without this capability,
   * calls to the returned API will not be authorized to perform asymmetric key
   * operations.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {string} options.type - The type of key
   *   (e.g. `Ed25519VerificationKey2018`).
   * @param {string} [options.capability=undefined] - The ID of the OCAP-LD
   *   authorization capability to use to authorize the invocation of the
   *   operations.
   *
   * @returns {Promise<Object>} The new Hmac instance.
   */
  async getAsymmetricKey({id, type, capability}) {
    const {kmsClient} = this;
    const invocationSigner = this;
    return new AsymmetricKey(
      {id, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Gets a KeyAgreementKey API for deriving shared secrets. The API will use
   * this ControllerKey instance to sign capability invocations to derive
   * shared secrets.
   *
   * If this ControllerKey is a controller of the KeyAgreementKey, then the API
   * for it can returned by passing only the key description. Otherwise, an
   * authorization capability must also be passed; without this capability,
   * calls to the returned API will not be authorized to perform key agreement
   * key operations.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {string} options.type - The type of key
   *   (e.g. `X25519KeyAgreementKey2019`).
   * @param {string} [options.capability=undefined] - The ID of the OCAP-LD
   *   authorization capability to use to authorize the invocation of the
   *   operations.
   *
   * @returns {Promise<Object>} The new Hmac instance.
   */
  async getKeyAgreementKey({id, type, capability}) {
    const {kmsClient} = this;
    const invocationSigner = this;
    return new KeyAgreementKey(
      {id, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Deterministically generates a key from a secret, a handle, and a
   * key name.
   *
   * @param {Object} options - The options to use.
   * @param {string|Uint8Array} [options.secret] - A secret to use as input
   *   when generating the key, e.g., a bcrypt hash of a password.
   * @param {string} options.handle - A semantic identifier that is mixed
   *   with the secret like a salt and, if `cache` is true, will be used to
   *   identify the seed in the cache. A common use for this field is to use
   *   the account ID for a user in a system.
   * @param {keyName} [options.keyName='root'] - An optional name to use to
   *   generate the key.
   * @param {boolean} [options.cache=true] - Use `true` to cache the seed for
   *   the key, `false` not to; a cached seed must be cleared via `clearCache`
   *   or it will persist until the user clears their local website storage.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Promise<ControllerKey>} The new ControllerKey instance.
   */
  static async fromSecret({
    secret, handle, keyName = 'root', cache = true,
    kmsClient = new KmsClient()
  }) {
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
    // TODO: instead of generating only one key from the seed, consider using
    // the seed in an HMAC that allows multiple other seeds to be generated,
    // allowing for multiple keys that can be generated via HMAC(keyName)
    //const key = await _keyFromSeedAndName({seed, keyName});
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
   *   create the key seed and differentiate it in the cache.
   * @param {keyName} [options.keyName='root'] - An optional name to use to
   *   generate the key.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {Promise<ControllerKey>} The new ControllerKey instance
   *   or `null` if no cached key for `handle` could be loaded.
   */
  static async fromCache(
    {handle, keyName = 'root', kmsClient = new KmsClient()}) {
    if(typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.');
    }
    const seed = await _seedCache.get(handle);
    if(!seed) {
      return null;
    }
    // TODO: instead of generating only one key from the seed, consider using
    // the seed in an HMAC that allows multiple other seeds to be generated,
    // allowing for multiple keys that can be generated via HMAC(keyName)
    //const key = await _keyFromSeedAndName({seed, keyName});
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

async function _keyFromSeedAndName({seed, keyName}) {
  const extractable = false;
  const key = await crypto.subtle.importKey(
    'raw', seed, {name: 'HMAC', hash: {name: 'SHA-256'}}, extractable,
    ['sign']);
  const nameBuffer = _stringToUint8Array(keyName);
  const signature = new Uint8Array(
    await crypto.subtle.sign(key.algorithm, key, nameBuffer));
  return _keyFromSeed({seed: signature});
}
