/*!
 * Copyright (c) 2026 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
const should = chai.should();

import {CapabilityAgent} from '../lib/index.js';

describe('CapabilityAgent.fromSecret', () => {
  describe('string secrets (behavior must not change)', () => {
    // Golden did:key values must remain stable; string-secret derivation is
    // unchanged by the binary-secret hashing fix.
    const goldens = [
      ['did:key:z6MkiS4sLV7Z3bWoV8PtgrrwDy41H2PciiWYY6jXwCc7RmHh',
        {secret: 'correct horse battery staple', handle: 'urn:example:alice'}],
      ['did:key:z6MkkoLvN3jJZhKuSz8o7y1Tjauti8xRB7o5v3z9zV4e3h8r',
        {secret: 'correct horse battery staple', handle: 'urn:example:alice',
          keyName: 'signing'}],
      ['did:key:z6MkfaUh2mPThm8BAApsDsb4YpiTQCJRJKRWtDBZjW4VmxW6',
        {secret: 's3cr3t', handle: 'acct:bob@example.com'}]
    ];

    for(const [expectedId, options] of goldens) {
      it(`derives ${expectedId}`, async () => {
        const agent = await CapabilityAgent.fromSecret(options);
        agent.id.should.equal(expectedId);
      });
    }

    it('derives different keys for different keyNames', async () => {
      const a = await CapabilityAgent.fromSecret(
        {secret: 'correct horse battery staple', handle: 'urn:example:alice'});
      const b = await CapabilityAgent.fromSecret({
        secret: 'correct horse battery staple', handle: 'urn:example:alice',
        keyName: 'signing'
      });
      a.id.should.not.equal(b.id);
    });
  });

  describe('binary secrets', () => {
    it('does not collapse distinct binary secrets to the same key',
      async () => {
        // Both 0xFF and 0xFE are invalid UTF-8; decoding the secret via
        // TextDecoder collapsed both to U+FFFD and derived an identical key.
        const a = await CapabilityAgent.fromSecret(
          {secret: new Uint8Array([0xff]), handle: 'h'});
        const b = await CapabilityAgent.fromSecret(
          {secret: new Uint8Array([0xfe]), handle: 'h'});
        a.id.should.match(/^did:key:/);
        b.id.should.match(/^did:key:/);
        a.id.should.not.equal(b.id);
      });

    it('derives a stable key for the same binary secret', async () => {
      const a = await CapabilityAgent.fromSecret(
        {secret: new Uint8Array([0, 1, 2, 3, 255]), handle: 'h'});
      const b = await CapabilityAgent.fromSecret(
        {secret: new Uint8Array([0, 1, 2, 3, 255]), handle: 'h'});
      a.id.should.equal(b.id);
    });

    it('matches the string secret for equivalent unreserved-ASCII bytes',
      async () => {
        const a = await CapabilityAgent.fromSecret(
          {secret: 'abc', handle: 'h'});
        const b = await CapabilityAgent.fromSecret(
          {secret: new Uint8Array([0x61, 0x62, 0x63]), handle: 'h'});
        a.id.should.equal(b.id);
      });
  });

  it('rejects a non-string, non-Uint8Array secret', async () => {
    let err;
    try {
      await CapabilityAgent.fromSecret({secret: 42, handle: 'h'});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.equal('"secret" must be a Uint8Array or a string.');
  });

  it('rejects a non-string handle', async () => {
    let err;
    try {
      await CapabilityAgent.fromSecret({secret: 's3cr3t', handle: 42});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    err.message.should.equal('"handle" must be a string.');
  });
});
