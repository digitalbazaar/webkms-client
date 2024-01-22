/*!
 * Copyright (c) 2019-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {AsymmetricKey} from './AsymmetricKey.js';
import {Hmac} from './Hmac.js';
import {Kek} from './Kek.js';
import {KeyAgreementKey} from './KeyAgreementKey.js';

export const RECOMMENDED_KEYS = new Map([
  ['asymmetric', {
    type: 'Ed25519VerificationKey2020',
    Class: AsymmetricKey
  }],
  ['hmac', {
    type: 'Sha256HmacKey2019',
    Class: Hmac
  }],
  ['keyAgreement', {
    type: 'X25519KeyAgreementKey2020',
    Class: KeyAgreementKey
  }],
  ['kek', {
    type: 'AesKeyWrappingKey2019',
    Class: Kek
  }]
]);
