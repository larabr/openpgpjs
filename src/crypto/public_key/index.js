/**
 * @fileoverview Asymmetric cryptography functions
 * @module crypto/public_key
 * @access private
 */

import enums from '../../enums.js';

export * as rsa from './rsa.js';
export * as elliptic from './elliptic/index.js';
export * as postQuantum from './post_quantum/index.js';

export async function getLegacyPublicKeyAlgorithm(algo) {
  switch (algo) {
    case enums.publicKey.elgamal:
    case enums.publicKey.dsa: {
      const { legacyPublicKeyAlgorithms } = await import('./legacy_public_keys/index.ts');
      const algoName = enums.read(enums.publicKey, algo);
      const publicKeyAlgo = legacyPublicKeyAlgorithms.get(algoName);
      if (!publicKeyAlgo) {
        throw new Error('Unsupported public key algorithm');
      }
      return publicKeyAlgo;
    }
    default:
      throw new Error('Unsupported public key algorithm');
  }
}
