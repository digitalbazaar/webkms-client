/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
const should = chai.should();

import * as kmsClient from '../lib/index.js';

describe('webkms-client API', () => {
  it('should have proper exports', async () => {
    should.exist(kmsClient);
    should.exist(kmsClient.AsymmetricKey);
    should.exist(kmsClient.CapabilityAgent);
    should.exist(kmsClient.Hmac);
    should.exist(kmsClient.Kek);
    should.exist(kmsClient.KeyAgreementKey);
    should.exist(kmsClient.KeystoreAgent);
    should.exist(kmsClient.KmsClient);
  });
});
