const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const chai = require('chai');
chai.use(require('chai-as-promised'));
const input = require('./testInputs.js');
const util = require('../../src/util');

const expect = chai.expect;
function computeECC(data) {
  const eccLength = Math.ceil(data.length / (16 * 8));
  const parities = new Uint8Array(eccLength); // 1 bit per 16 bytes -> 17 bytes: 2 bits, 1 bytes; 128 bytes -> 8 bit; 1 byte, 129 bytes -> 8 bits, two bytes
  // const u16 = new Uint16Array(1);
  // for (let i = 0; i < data.length; i += 2) {
  //   const getParity = x => {
  //     // https://stackoverflow.com/questions/17350906/computing-the-parity
  //     let y = x ^ (x >> 1);
  //     y = y ^ (y >> 2);
  //     y = y ^ (y >> 4);
  //     y = y ^ (y >> 8);
  //     // y = y ^ (y >> 16);
  //     return y & 1;
  //   };
  //   u16[0] = (data[i] << 8) | data[i + 1];
  //   const byteIndex = Math.floor(i / (16 * 8));
  //   const bitIndex = Math.floor(i / 16);
  //   parities[byteIndex] = parities[byteIndex] | (getParity(u16) << bitIndex);
  //   console.log(`byte ${byteIndex}/bit ${bitIndex} (${u16.subarray(0)}), parity: ${getParity(u16)}; total: ${parities[byteIndex]}`);

  // }
  const u32 = new Uint32Array(4);
  console.log('')
  // process 16 bytes at a time (i.e. 1 parity bit)
  for (let i = 0; i < data.length; i += 16) {
    const getParity = x => {
      // parity of a Uint32 value
      // https://stackoverflow.com/questions/17350906/computing-the-parity
      let y = x ^ (x >> 1);
      y = y ^ (y >> 2);
      y = y ^ (y >> 4);
      y = y ^ (y >> 8);
      y = y ^ (y >> 16);
      return y & 1;
    };
    // endianess does not matter for parity
    u32[0] = data[i + 0] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 32);
    u32[1] = data[i + 4] | (data[i + 5] << 8) | (data[i + 6] << 16) | (data[i + 7] << 32);
    u32[2] = data[i + 8] | (data[i + 9] << 8) | (data[i + 10] << 16) | (data[i + 11] << 32);
    u32[3] = data[i + 12] | (data[i + 13] << 8) | (data[i + 14] << 16) | (data[i + 15] << 32);

    const byteIndex = Math.floor(i / (16 * 8));
    const bitIndex = Math.floor(i / 16);
    const parity = getParity(u32[0]) ^ getParity(u32[1]) ^ getParity(u32[2]) ^ getParity(u32[3]);
    parities[byteIndex] = parities[byteIndex] | (parity << bitIndex);
    console.log(`byte ${byteIndex}/bit ${bitIndex} (${u32.subarray(0)}), parity: ${parity}; total: ${parities[byteIndex]}`);

  }
  return parities;
}

// return lower and upper bound of range of bytes that contain corruption
function findCorruption(decrypted, ecc) {
  const decryptedECC = computeECC(decrypted);
  console.log(decryptedECC, ecc);

  // expect(decryptedECC).to.not.deep.equal(ecc);
  if (util.equalsUint8Array(decryptedECC, ecc)) {
    // this means the tag was corrupted
    throw new Error('same ECC');
  }
  expect(decryptedECC.length).to.equal(ecc.length);
  for (let i = 0; i < ecc.length; i++) {
    if (ecc[i] !== decryptedECC[i]) {
      // NB: multiple bits will differ (1 bit corruption scrambles next AES block)
      const diff = ecc[i] ^ decryptedECC[i];
      for (let j = 0; j < 8; j++) {
        if ((diff >> j) & 1) {
          const lower = i * 16 * 8 + j * 16;
          return { lower, upper: lower + 15 };
        }
      }
    }
  }
  throw new Error('no corruption detected')
}

async function recover(binaryMessage, range, original) {
  let data;

  console.log('attempting recovery', binaryMessage.length)
  const bits = [1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5, 1 << 6, 1 << 7]
  for (let i = range.lower; i <= range.upper; i++) {
    console.log(i)
    // eslint-disable-next-line no-loop-func
    const promises = await Promise.all(bits.map(async bit => {
      // copy message before flipping
      // can be optimised by using the same array for each 'bit' and "flipping back" the bit after decryption (sharing the array across promises might give concurrency issues...? i.e. multiple bitflips applied in a given promise)
      const flipped = binaryMessage.slice(0);
      flipped[i] = flipped[i] ^ bit;
      // try { // decryption won't throw since integrity check is disabled, for testing
        const res = await openpgp.decrypt({
          message: await openpgp.readMessage({ binaryMessage: flipped }),
          passwords: 'password',
          format: 'binary',
        });
        if (util.equalsUint8Array(res.data, original)) { // in final implementation, we'd just check that authentication of decryption suceeds, but here i have had to disable the integrity check for testing...
          console.log('found bit', bit, i)
          return true;
        } else {
          if (i === 100) {
            console.log(binaryMessage, flipped, res.data)
          }
        }
      // } catch (e) {
      //   // console.log(e)
      //   // console.log('bit did not work: ', i, bit)
      //   // undo bitflip
      //   console.log('thrown ', e)
      //   flipped[i] = flipped[i] ^ bit;
      // }
    }))
    // exactly one decryption should succeed
    if (promises.filter(Boolean).length === 1) return true;
  }
  return false; // no recovery
}

module.exports = () => describe('Drive bitflip prevention', function () {
  it('computeECC', async function () {
    // const FILESIZE = 24 * 1000000; // in MB, should be multiple of 4
    // const testData = crypto.getRandomValues(new Uint8Array(FILESIZE));

    expect(computeECC(new Uint8Array([0,0,255,0,0]))).to.deep.equal(new Uint8Array([0]));
    expect(computeECC(new Uint8Array([0,0,1,0,0]))).to.deep.equal(new Uint8Array([1]));
    expect(computeECC(new Uint8Array(new Array(17).fill(1)))).to.deep.equal(new Uint8Array([2])); // 1 0
    // expect(computeECC(new Uint8Array([2, 1, 1, 1, 1]))).to.deep.equal(new Uint8Array([4])); // 1 0 0
    // BYTE 0, BIT 0: 0x02 0x01 - 0xff 0x01 - 0xff 0xff - ... 0xff 0xff ---> odd
    // BYTE 0, BIT 1: 0xff
    expect(computeECC(new Uint8Array([2, 1, 255, 1].concat(new Array(13).fill(1))))).to.deep.equal(new Uint8Array([2])); // 1 1

  });

  it('recover file CFB', async function () {
    const FILESIZE = 1000;// 24 * 1000000; // in MB, should be multiple of 4
    const testData = new Uint8Array(FILESIZE)//crypto.getRandomValues(new Uint8Array(FILESIZE));
    const eccData = computeECC(testData);
    const message = await openpgp.createMessage({ binary: testData });
    const startIndex = (() => {
      const bytes = message.packets.write();
      for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === testData[0] && bytes[i+1] === testData[1] && bytes[i+2] === testData[2] && bytes[i+3] === testData[3]) {
          // skip random prefix (16 + 2 bytes) that will be prepanded to plaintext before encryption
          return i + 18;
        }
      }
      throw new Error('start index not found')
    })();
    const encrypted = await openpgp.encrypt({
      message,
      passwords: 'password',
      format: 'binary'
    });

    // corrupt
    console.log(encrypted)
    encrypted[100] = encrypted[100] ^ 0x02;
    const { data: decrypted } = await openpgp.decrypt({
      message: await openpgp.readMessage({ binaryMessage: encrypted }),
      passwords: 'password',
      format: 'binary'
    });
    const { lower, upper } = findCorruption(decrypted, eccData);
    const corruptedMessage = await openpgp.readMessage({ binaryMessage: encrypted });
    // console.log(corruptedMessage.packets)
    console.log(decrypted, testData)
    // console.log(byte, startIndex)
    console.log()
    const expectedCorruptionIndex = decrypted.findIndex(x => x !== 0);
    expect(expectedCorruptionIndex >= lower && expectedCorruptionIndex <= upper).to.be.true;
    // expect(byte + startIndex).to.equal(100);
    // corruptedMessage.packets[1].encrypted[0][startIndex + 21] = corruptedMessage.packets[1].encrypted[0][startIndex + 21] ^ 1;
    // 'encrypted' serialised data includes also ESK packet, and the existing lower/upper are only relative to the SEIP payload
    const rangeOffset = startIndex + corruptedMessage.packets[0].write().length;
    console.log('offset', rangeOffset)
    expect(await recover(encrypted, { lower: lower + rangeOffset, upper: upper + rangeOffset }, testData)).to.be.true;

  });

  it('recover file GCM', async function () {
    // NB: must use asmcrypto otherwise web
    const FILESIZE = 1000;// 24 * 1000000; // in MB, should be multiple of 4
    const testData = new Uint8Array(FILESIZE)//crypto.getRandomValues(new Uint8Array(FILESIZE));
    const eccData = computeECC(testData);
    const message = await openpgp.createMessage({ binary: testData });
    const startIndex = (() => {
      const bytes = message.packets.write();
      for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === testData[0] && bytes[i+1] === testData[1] && bytes[i+2] === testData[2] && bytes[i+3] === testData[3]) {
          // skip IV, that will be prepended to ciphertext on serialisation
          return i + 12;
        }
      }
      throw new Error('start index not found')
    })();
    const encrypted = await openpgp.encrypt({
      message,
      passwords: 'password',
      format: 'binary',
      config: {
        aeadProtect: true,
        preferredAEADAlgorithm: openpgp.enums.aead.experimentalGCM
      }
    });

    // corrupt
    const tmp = await openpgp.readMessage({ binaryMessage: encrypted })
    console.log(tmp, tmp.packets[0].write().length)
    encrypted[120] = encrypted[120] ^ 0x02;
    const { data: decrypted } = await openpgp.decrypt({
      message: await openpgp.readMessage({ binaryMessage: encrypted }),
      passwords: 'password',
      format: 'binary'
    });
    try {
      const { lower, upper } = findCorruption(decrypted, eccData);
      const corruptedMessage = await openpgp.readMessage({ binaryMessage: encrypted });
      // console.log(corruptedMessage.packets)
      console.log(decrypted, testData)
      // console.log(byte, startIndex)
      console.log()
      const expectedCorruptionIndex = decrypted.findIndex(x => x !== 0);
      expect(expectedCorruptionIndex >= lower && expectedCorruptionIndex <= upper).to.be.true;
      // expect(byte + startIndex).to.equal(100);
      // corruptedMessage.packets[1].encrypted[0][startIndex + 21] = corruptedMessage.packets[1].encrypted[0][startIndex + 21] ^ 1;
      // 'encrypted' serialised data includes also ESK packet, and the existing lower/upper are only relative to the SEIP payload
      const rangeOffset = startIndex + corruptedMessage.packets[0].write().length;
      expect(await recover(encrypted, { lower: lower + rangeOffset, upper: upper + rangeOffset }, testData)).to.be.true;
  
    } catch {
      throw new Error('not testing auth tag corruption')
      // corruption affected the Auth tags, we can just force decryption
      const { data: forceDecryptedData } = await openpgp.decrypt({
        message: await openpgp.readMessage({ binaryMessage: encrypted }),
        passwords: 'password',
        format: 'binary'
      });
      expect(forceDecryptedData).to.deep.eq(testData)
    }
    
  });
});
