/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
const should = chai.should();

import {AsymmetricKey} from '../lib/index.js';

const keys = new Map([
  ['ed25519', 'did:key:z6MkoQjzqWih7kG3VSQy95reUwLeAT2FHLUqKsR2aXzZdB3g'],
  ['p256', 'did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169'],
  ['p384', 'did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcV' +
    'BgjGhnLBn2Kaau9'],
  ['p521', 'did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7S' +
    'zcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7'],
  ['secp256k1', 'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme']
]);

describe('AsymmetricKey API', () => {
  describe('should create key from keyDescription', () => {
    for(const [keyType, did] of keys) {
      it(`key type ${keyType}`, async () => {
        const keyDescription = {
          id: did,
          type: keyType,
          publicKeyMultibase: did.substr(8)
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
});
