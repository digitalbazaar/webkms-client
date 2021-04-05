/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
import {CryptoLD} from 'crypto-ld';
import {Ed25519VerificationKey2018} from
  '@digitalbazaar/ed25519-verification-key-2018';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {X25519KeyAgreementKey2019} from
  '@digitalbazaar/x25519-key-agreement-key-2019';
import {X25519KeyAgreementKey2020} from
  '@digitalbazaar/x25519-key-agreement-key-2020';

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2018);
cryptoLd.use(Ed25519VerificationKey2020);
cryptoLd.use(X25519KeyAgreementKey2019);
cryptoLd.use(X25519KeyAgreementKey2020);

export {cryptoLd};
