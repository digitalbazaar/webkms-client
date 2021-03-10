/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from './crypto.js';
import {CryptoLD} from 'crypto-ld';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {SeedCache} from './SeedCache.js';
import {TextDecoder, TextEncoder} from './util.js';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';
import {X25519KeyPair} from 'x25519-key-pair';
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2018);
cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyPair);
const _seedCache = new SeedCache();

export class CapabilityAgent {
  /**
   * Creates a new instance of a CapabilityAgent that uses a KmsClient
   * instance that is, by default, bound to a particular keystore.
   *
   * A CapabilityAgent can provide an `invocationSigner` to a KmsClient
   * via its `getSigner` API, but a KmsClient instance is typically
   * used internally by other instances that can be created via
   * the CapabilityAgent API such as instances of the Kek and Hmac classes.
   *
   * The CapabilityAgent constructor should never be called directly. It
   * should always be created via a static method on the class. Use one of the
   * static methods in the examples to create a CapabilityAgent instance.
   *
   * @example
   * CapabilityAgent.fromSecret();
   * CapabilityAgent.fromCache();
   * CapabilityAgent.fromBiometric();
   * CapabilityAgent.fromFido();
   *
   * @param {object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create the key.
   * @param {object} options.signer - An API with an `id` property, a
   *   `type` property, and a `sign` function.
   * @param {Ed25519VerificationKey2020} options.keyPair - Underlying key pair.
   *
   * @returns {CapabilityAgent} The new instance.
   */
  constructor({handle, signer, keyPair}) {
    this.handle = handle;
    // signer is a did:key
    this.id = signer.id.split('#')[0];
    this.signer = signer;
    // reference to core key pair used for invocation signing
    this._keyPair = keyPair;
  }

  /**
   * Gets a signer API, typically for signing capability invocation or
   * delegation proofs.
   *
   * @returns {object} An API with an `id` property, a `type` property, and a
   *   `sign` function.
   */
  getSigner() {
    return this.signer;
  }

  /**
   * Deterministically generates a CapabilityAgent from a secret, a semantic
   * handle to uniquely identify the secret, and a key name. The same secret
   * can be used to generate multiple keys by using different key names.
   *
   * @param {object} options - The options to use.
   * @param {string|Uint8Array} [options.secret] - A secret to use as input
   *   when generating the key, e.g., a bcrypt hash of a password.
   * @param {string} options.handle - A semantic identifier for the secret
   *   that is mixed with it like a salt to produce a seed, and, if `cache` is
   *   true, will be used to identify the seed in the cache. A common use for
   *   this field is to use the account ID for a user in a system.
   * @param {string} [options.keyName='root'] - An optional name to use to
   *   generate the key.
   * @param {boolean} [options.cache=true] - Use `true` to cache the seed for
   *   the key, `false` not to; a cached seed must be cleared via `clearCache`
   *   or it will persist until the user clears their local website storage.
   * @param {string} options.keyType - A signature key type, for example:
   *   Ed25519VerificationKey2018 or Ed25519VerificationKey2020.
   *
   * @returns {Promise<CapabilityAgent>} The new CapabilityAgent instance.
   */
  static async fromSecret({
    secret, handle, keyName = 'default', cache = true, keyType
  }) {
    if(typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.');
    }
    if(typeof keyType !== 'string') {
      throw new TypeError('"keyType" must be a string.');
    }
    if(typeof secret === 'string') {
      secret = _stringToUint8Array(secret);
    } else if(!(secret instanceof Uint8Array)) {
      throw new TypeError('"secret" must be a Uint8Array or a string.');
    }

    // compute salted SHA-256 hash as the seed for the key
    const seed = await _computeSaltedHash({secret, salt: handle});
    const {signer, keyPair} = await _keyFromSeedAndName({
      seed, keyName, keyType
    });
    // cache seed if requested
    if(cache) {
      await _seedCache.set(handle, seed);
    }

    return new CapabilityAgent({handle, signer, keyPair});
  }

  static async fromBiometric() {
    throw new Error('Not implemented.');
  }

  static async fromFido() {
    throw new Error('Not implemented.');
  }

  /**
   * Loads a CapabilityAgent from a local cache if available. This method
   * will only work if it has been previously cached. To clear
   * this CapabilityAgent to prevent future loading, call `clearCache` with
   * the CapabilityAgent's `handle`.
   *
   * @param {object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create a seed for the CapabilityAgent and differentiate it in the
   *   cache.
   * @param {string} [options.keyName='default'] - An optional name to use to
   *   generate the root key for the CapabilityAgent.
   *
   * @returns {Promise<CapabilityAgent>} The new CapabilityAgent instance
   *   or `null` if no cached CapabilityAgent for `handle` could be loaded.
   */
  static async fromCache({handle, keyName = 'default'}) {
    if(typeof handle !== 'string') {
      throw new TypeError('"handle" must be a string.');
    }
    const seed = await _seedCache.get(handle);
    if(!seed) {
      return null;
    }
    const {signer, keyPair} = await _keyFromSeedAndName({seed, keyName});
    return new CapabilityAgent({handle, signer, keyPair});
  }

  /**
   * Clears a CapabilityAgent from any caches. This must be called for
   * any CapabilityAgents created via `fromSecret` with `cache` set to
   * `true` in order to ensure it cannot be loaded via `fromCache`.
   *
   * @param {object} options - The options to use.
   * @param {string} options.handle - The semantic identifier that was used to
   *   create the CapabilityAgent and differentiate it in the cache.
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

async function _computeSaltedHash({secret, salt}) {
  // compute salted SHA-256 hash
  salt = _uint8ArrayToString(salt);
  secret = _uint8ArrayToString(secret);
  const toHash = _stringToUint8Array(
    `${encodeURIComponent(salt)}:${encodeURIComponent(secret)}`);
  const algorithm = {name: 'SHA-256'};
  return new Uint8Array(await crypto.subtle.digest(algorithm, toHash));
}

async function _keyFromSeedAndName({seed, keyName, keyType}) {
  const extractable = false;
  const hmacKey = await crypto.subtle.importKey(
    'raw', seed, {name: 'HMAC', hash: {name: 'SHA-256'}}, extractable,
    ['sign']);
  const nameBuffer = _stringToUint8Array(keyName);
  const signature = new Uint8Array(
    await crypto.subtle.sign(hmacKey.algorithm, hmacKey, nameBuffer));
  // generate Ed25519 key from HMAC signature
  const keyPair = await cryptoLd.generate({seed: signature, type: keyType});

  // create key and specify ID for key using fingerprint
  const signer = keyPair.signer();
  const fingerprint = keyPair.fingerprint();
  signer.id = `did:key:${fingerprint}#${fingerprint}`;
  signer.type = keyPair.type;
  return {signer, keyPair};
}
