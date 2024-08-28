/*!
 * Copyright (c) 2020-2024 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
const should = chai.should();

import {AsymmetricKey} from '../lib/index.js';

const keys = new Map([
  // eslint-disable-next-line
  ['Bls12381G2', 'did:key:zUC7DerdEmfZ8f4pFajXgGwJoMkV1ofMTmEG5UoNvnWiPiLuGKNeqgRpLH2TV4Xe5mJ2cXV76gRN7LFQwapF1VFu6x2yrr5ci1mXqC1WNUrnHnLgvfZfMH7h6xP6qsf9EKRQrPQ'],
  ['Ed25519', 'did:key:z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g'],
  ['P-256', 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169'],
  ['P-384', 'did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcV' +
    'BgjGhnLBn2Kaau9'],
  ['P-521', 'did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7S' +
    'zcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7'],
  ['secp256k1', 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme']
]);

const badKeys = new Map([
  // key from a test with unkonwn 'zUC6' prefix
  // eslint-disable-next-line
  ['Bls12381G2', 'did:key:zUC6zwkczByHEDfap8UJdBwLDeiTYn2xUBq5AhYDnH3Actf9RgdvVF3Rqc2DaYh8j6JysZ6HLidVxM2Y2AhTtM7a5GefA2DGv6JJuSaTJ7ov1jtCnQLmAFYJoovhdzj2kivX9ev'],
]);

describe('AsymmetricKey API', () => {
  describe('should create key from keyDescription', () => {
    for(const [keyType, did] of keys) {
      it(`key type ${keyType}`, async () => {
        const keyDescription = {
          id: did,
          type: keyType,
          publicKeyMultibase: did.slice(8)
        };
        const key = new AsymmetricKey({keyDescription});
        should.exist(key, 'Expected a key to exist');
        should.exist(key.algorithm, 'Expected "key.algorithm" to exist');
        key.algorithm.should.be.a('string');
        key.algorithm.should.eql(
          keyType,
          `Expected "key.algorithm" to be ${keyType}`
        );
      });
    }
  });
  describe('should fail for bad keys', () => {
    for(const [keyType, did] of badKeys) {
      it(`key type ${keyType}`, async () => {
        let error;
        let key;
        try {
          const keyDescription = {
            id: did,
            type: keyType,
            publicKeyMultibase: did.slice(8)
          };
          key = new AsymmetricKey({keyDescription});
        } catch(e) {
          error = e;
        }
        should.exist(error, 'Expected error to exist');
        should.not.exist(key, 'Expected key to not exist');
      });
    }
  });
});
