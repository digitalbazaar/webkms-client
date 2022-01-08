/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {AsymmetricKey} from './AsymmetricKey.js';
import {Kek} from './Kek.js';
import {KeyAgreementKey} from './KeyAgreementKey.js';
import {Hmac} from './Hmac.js';
import {KmsClient} from './KmsClient.js';
import {RECOMMENDED_KEYS} from './recommendedKeys.js';

const VERSIONS = ['recommended', 'fips'];

/**
 * @class CapabilityAgent
 */

export class KeystoreAgent {
  /**
   * Creates a new instance of a KeystoreAgent that uses the
   * given CapabilityAgent and KmsClient to interact with a keystore. If
   * the CapabilityAgent is a controller of the keystore and will be using
   * root capabilities to access it, then the keystore's configuration must
   * also be given.
   *
   * @param {object} options - The options to use.
   * @param {CapabilityAgent} options.capabilityAgent - The CapabilityAgent
   *   to use to interact with the keystore.
   * @param {string} [options.keystoreId] - The ID for the keystore; only
   *   needed if interacting with the keystore as its controller.
   * @param {KmsClient} [options.kmsClient] - An optional KmsClient to use.
   *
   * @returns {KeystoreAgent} The new instance.
   */
  constructor({capabilityAgent, keystoreId, kmsClient = new KmsClient()}) {
    if(keystoreId && typeof keystoreId !== 'string') {
      throw new TypeError('"keystoreId" must be a string.');
    }

    this.capabilityAgent = capabilityAgent;
    this.keystoreId = keystoreId;
    this.kmsClient = kmsClient;
    if(this.keystoreId) {
      this.kmsClient.keystoreId = keystoreId;
    }
  }

  /**
   * Generates a key in the keystore associated with the internal KmsClient.
   * To use the latest recommended key algorithms, specify the key type as
   * `hmac`, `kek`, `keyAgreement`, or `asymmetric`. A key can be generated
   * using a FIPS-compliant algorithm or the latest recommended algorithm
   * (default).
   *
   * To generate a key using a custom algorithm of your choice, you'll need to
   * use the `KmsClient` class directly and instantiate the key interface that
   * is appropriate for the type of key being generated.
   *
   * @example
   * await generateKey({type: 'keyAgreement'})
   *
   * @param {object} options - The options to use.
   * @param {string} options.type - The type of key to create (e.g., `hmac`).
   * @param {string} [options.publicAlias] - The public alias to use for the
   *   key, if it is an asymmetric key.
   * @param {string} [options.publicAliasTemplate] - The public alias template
   *   to use for the key, if it is an asymmetric key.
   * @param {string} [options.version=recommended] - `fips` to
   *   use FIPS-compliant ciphers, `recommended` to use the latest recommended
   *   ciphers.
   *
   * @returns {Promise<object>} An Hmac, Kek, AsymmetricKey, or KeyAgreementKey
   *   instance.
   */
  async generateKey({
    type, publicAlias, publicAliasTemplate, version = 'recommended'
  } = {}) {
    _assertVersion(version);

    // for the time being, fips and recommended are the same; there is no
    // other standardized key wrapping algorithm
    const keyDetails = RECOMMENDED_KEYS.get(type);
    if(!keyDetails) {
      throw new Error(`Unknown key type "${type}".`);
    }
    const {type: fullType, suiteContextUrl, Class} = keyDetails;

    const {capabilityAgent, kmsClient} = this;
    const invocationSigner = capabilityAgent.getSigner();
    const keyDescription = await kmsClient.generateKey({
      type: fullType, suiteContextUrl, invocationSigner,
      publicAlias, publicAliasTemplate
    });
    const {id} = keyDescription;
    ({type} = keyDescription);
    return new Class({id, type, invocationSigner, kmsClient, keyDescription});
  }

  /**
   * Gets a KEK API for wrapping and unwrapping cryptographic keys. The API
   * will use this KeystoreAgent instance to sign capability invocations to
   * wrap or unwrap keys.
   *
   * If this KeystoreAgent's CapabilityAgent is a controller of the KEK, then
   * the API for it can be returned by passing only the key id and type.
   * Otherwise, an Authorization Capability (zcap) must also be passed;
   * without this capability, calls to the returned API will not be authorized
   * to perform KEK operations.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {string} options.type - The type of key
   *   (e.g. `AesKeyWrappingKey2019`).
   * @param {object} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of the operations.
   *
   * @returns {Promise<object>} The new Kek instance.
   */
  async getKek({id, type, capability}) {
    const {capabilityAgent, kmsClient} = this;
    const invocationSigner = capabilityAgent.getSigner();
    if(capability) {
      return Kek.fromCapability({capability, invocationSigner, kmsClient});
    }
    return new Kek({id, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Gets an HMAC API for signing and verifying data. The API
   * will use this KeystoreAgent instance to sign capability invocations to
   * sign or verify data.
   *
   * If this KeystoreAgent's CapabilityAgent is a controller of the HMAC, then
   * the API for it can be returned by passing only the key id and type.
   * Otherwise, an Authorization Capability (zcap) must also be passed;
   * without this capability, calls to the returned API will not be authorized
   * to perform HMAC operations.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The ID of the key.
   * @param {string} options.type - The type of key (e.g. `Sha256HmacKey2019`).
   * @param {object} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of the operations.
   *
   * @returns {Promise<object>} The new Hmac instance.
   */
  async getHmac({id, type, capability}) {
    const {capabilityAgent, kmsClient} = this;
    const invocationSigner = capabilityAgent.getSigner();
    if(capability) {
      return Hmac.fromCapability({capability, invocationSigner, kmsClient});
    }
    return new Hmac({id, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Gets an AsymmetricKey API for signing and verifying data. The API
   * will use this KeystoreAgent instance to sign capability invocations to
   * sign or verify data.
   *
   * If this KeystoreAgent's CapabilityAgent is a controller of
   * the AsymmetricKey, then the API for it can be returned by passing only the
   * key id and type. Otherwise, an Authorization Capability (zcap) must also
   * be passed; without this capability, calls to the returned API will not be
   * authorized to perform asymmetric key operations.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The public ID of the key; if the public ID
   *   is different from the private KMS ID, pass it separately as `kmsId`.
   * @param {string} [options.kmsId=options.id] - The private ID of this key
   *   with the KMS.
   * @param {string} options.type - The type of key
   *   (e.g. `Ed25519VerificationKey2020`).
   * @param {object} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of the operations.
   *
   * @returns {Promise<object>} The new Hmac instance.
   */
  async getAsymmetricKey({id, kmsId, type, capability}) {
    const {capabilityAgent, kmsClient} = this;
    const invocationSigner = capabilityAgent.getSigner();
    if(capability) {
      return AsymmetricKey.fromCapability(
        {capability, invocationSigner, kmsClient});
    }
    return new AsymmetricKey(
      {id, kmsId, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Gets a KeyAgreementKey API for deriving shared secrets. The API will use
   * this KeystoreAgent instance to sign capability invocations to derive
   * shared secrets.
   *
   * If this KeystoreAgent's CapabilityAgent is a controller of
   * the KeyAgreementKey, then the API for it can be returned by passing only
   * the key id and type. Otherwise, an Authorization Capability (zcap) must
   * also be passed; without this capability, calls to the returned API will
   * not be authorized to perform key agreement key operations.
   *
   * @param {object} options - The options to use.
   * @param {string} options.id - The public ID of the key; if the public ID
   *   is different from the private KMS ID, pass it separately as `kmsId`.
   * @param {string} [options.kmsId=options.id] - The private ID of this key
   *   with the KMS.
   * @param {string} options.type - The type of key
   *   (e.g. `X25519KeyAgreementKey2020`).
   * @param {object} [options.capability] - The zCAP-LD authorization
   *   capability to use to authorize the invocation of the operations.
   *
   * @returns {Promise<object>} The new Hmac instance.
   */
  async getKeyAgreementKey({id, kmsId, type, capability}) {
    const {capabilityAgent, kmsClient} = this;
    const invocationSigner = capabilityAgent.getSigner();
    if(capability) {
      return KeyAgreementKey.fromCapability(
        {capability, invocationSigner, kmsClient});
    }
    return new KeyAgreementKey(
      {id, kmsId, type, capability, invocationSigner, kmsClient});
  }

  /**
   * Update a keystore using the given configuration.
   *
   * @param {object} options - The options to use.
   * @param {string} [options.capability] - The ZCAP authorization
   *   capability to use to authorize the invocation of this operation.
   * @param {string} options.config - The keystore's configuration.
   *
   * @returns {Promise<object>} Resolves to the new keystore configuration.
   */
  async updateConfig({capability, config}) {
    const {capabilityAgent, kmsClient} = this;
    const invocationSigner = capabilityAgent.getSigner();
    return kmsClient.updateKeystore({capability, config, invocationSigner});
  }
}

function _assertVersion(version) {
  if(typeof version !== 'string') {
    throw new TypeError('"version" must be a string.');
  }
  if(!VERSIONS.includes(version)) {
    throw new Error(`Unsupported version "${version}"`);
  }
}
