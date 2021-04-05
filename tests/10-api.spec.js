/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
const chai = require('chai');
const should = chai.should();

const kmsClient = require('..');

describe('webkms-client API', () => {
  it('should have proper exports', async () => {
    should.exist(kmsClient);
    kmsClient.should.have.property('AsymmetricKey');
    kmsClient.should.have.property('CapabilityAgent');
    kmsClient.should.have.property('Hmac');
    kmsClient.should.have.property('Kek');
    kmsClient.should.have.property('KeyAgreementKey');
    kmsClient.should.have.property('KeystoreAgent');
    kmsClient.should.have.property('KmsClient');
  });
});
