/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import {AsymmetricKey} from './AsymmetricKey.js';
import {Hmac} from './Hmac.js';
import {Kek} from './Kek.js';
import {KeyAgreementKey} from './KeyAgreementKey.js';

export const CATEGORY_TO_CLASS = new Map([
  ['asymmetric', AsymmetricKey],
  ['hmac', Hmac],
  ['keyAgreement', KeyAgreementKey],
  ['kek', Kek]
]);
