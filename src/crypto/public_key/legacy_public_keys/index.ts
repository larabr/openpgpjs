/**
 * @access private
 * This file is needed to dynamic import the legacy public key algos.
 * Separate dynamic imports are not convenient as combinations of these
 * are typically used together
 */

import * as elgamal from './elgamal.js';
import * as dsa from './dsa.js';

// We avoid importing 'enums' as this module is lazy loaded, and doing so could mess up
// chunking for the lightweight build
export const legacyPublicKeyAlgorithms = new Map(Object.entries({
  elgamal,
  dsa
}));
