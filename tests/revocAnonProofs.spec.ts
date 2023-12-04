import * as jsonld from 'jsonld';
import { describe, expect, test } from 'vitest';
import {
  sign,
  deriveProof,
  verifyProof,
  ellipticElGamalKeyGen,
  ellipticElGamalDecrypt,
  getEncryptedUid,
} from '../src/api';
import { localDocumentLoader } from './documentLoader';
import disclosed0_bound from './example/disclosed0_bound.json';
import keypairs from './example/keypairs.json';
import vcDraft0Bound from './example/vc0_bound.json';
import _vpContext from './example/vpContext.json';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;

describe('Revocable Anonymity Proofs', () => {
  test('deriveProof and verifyProof', async () => {
    const userId = new Uint8Array(Buffer.from('908d29e9-9fd5-4e80-955f-8bcc3a833510'));

    const encryptedUid = await getEncryptedUid(userId);

    const vc0 = await sign(vcDraft0Bound, keypairs, localDocumentLoader, userId);

    console.log(vc0);
    const { publicKey, secretKey } = await ellipticElGamalKeyGen();

    const challenge = 'abcde';
    const vp = await deriveProof(
      [{ original: vc0, disclosed: disclosed0_bound }],
      keypairs,
      vpContext,
      localDocumentLoader,
      { challenge, secret: userId, openerPubKey: publicKey },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
      openerPubKey: publicKey,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();

    const decryptedValue = await ellipticElGamalDecrypt(
      secretKey,
      vp.proof['https://sako-lab.jp/schemas#encrypted_uid'],
    );
    console.log({ publicKey, secretKey } )

    expect(decryptedValue).toEqual(encryptedUid);
  });
});
