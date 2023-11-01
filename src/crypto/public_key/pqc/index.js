import util from '../../../util';
import * as ecdhX from './kem_ecdh_x';
import * as ml from './kem_ml';

const kem = { ecdhX, ml, multiKeyCombine };
export {
  kem
};

async function multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, outputBits) {
  //   multiKeyCombine(eccKeyShare, eccCipherText,
  //                   mlkemKeyShare, mlkemCipherText,
  //                   fixedInfo, oBits)
  //
  //   Input:
  //   eccKeyShare     - the ECC key share encoded as an octet string
  //   eccCipherText   - the ECC ciphertext encoded as an octet string
  //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
  //   mlkemCipherText - the ML-KEM ciphertext encoded as an octet string
  //   fixedInfo       - the fixed information octet string
  //   oBits           - the size of the output keying material in bits
  //
  //   Constants:
  //   domSeparation       - the UTF-8 encoding of the string
  //                         "OpenPGPCompositeKeyDerivationFunction"
  //   counter             - the fixed 4 byte value 0x00000001
  //   customizationString - the UTF-8 encoding of the string "KDF"
  const { kmac256 } = await import('@openpgp/noble-hashes/sha3-addons');
  // const { eccKeyShare, eccCiphertext } = await publicKey.pqc.kem.ecdhX(keyAlgo, publicParams.A);
  // const { keyShare: mlkemKeyShare, cipherText: mlkemCipherText } = await publicKey.pqc.kem.ml(keyAlgo, publicParams.publicKey);
  const eccData = util.concatUint8Array([eccKeyShare, eccCipherText]); // eccKeyShare || eccCipherText
  const mlkemData = util.concatUint8Array([mlkemKeyShare, mlkemCipherText]); //mlkemKeyShare || mlkemCipherText
  // const fixedInfo = new Uint8Array([keyAlgo]);
  const encData = util.concatUint8Array([
    new Uint8Array([1, 0, 0, 0]),
    eccData,
    mlkemData,
    fixedInfo
  ]); // counter || eccData || mlkemData || fixedInfo

  const mb = kmac256(
    util.encodeUTF8('OpenPGPCompositeKeyDerivationFunction'),
    encData,
    { personalization: util.encodeUTF8('KDF') }
  );

  return mb;
}
