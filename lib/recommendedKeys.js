/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
import {AsymmetricKey} from './AsymmetricKey.js';
import {Kek} from './Kek.js';
import {KeyAgreementKey} from './KeyAgreementKey.js';
import {Hmac} from './Hmac.js';

export const RECOMMENDED_KEYS = new Map([
  ['asymmetric', {
    type: 'Ed25519VerificationKey2020',
    suiteContextUrl: 'https://w3id.org/security/suites/ed25519-2020/v1',
    Class: AsymmetricKey
  }],
  ['hmac', {
    type: 'Sha256HmacKey2019',
    suiteContextUrl: 'https://w3id.org/security/suites/hmac-2019/v1',
    Class: Hmac
  }],
  ['keyAgreement', {
    type: 'X25519KeyAgreementKey2020',
    suiteContextUrl: 'https://w3id.org/security/suites/x25519-2020/v1',
    Class: KeyAgreementKey
  }],
  ['kek', {
    type: 'AesKeyWrappingKey2019',
    suiteContextUrl: 'https://w3id.org/security/suites/aes-2019/v1',
    Class: Kek
  }]
]);
