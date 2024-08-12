import { readMessage } from 'openpgp';

const expected = ['This message / key probably does not conform to a valid OpenPGP format', 'Unexpected end of packet', 'This packet type does not support partial length', 'Invalid enum value', 'Unknown packet type', 'Packet not allowed in this context', 'bytes', 'not supported', 'unexpected end of fil', 'Missing signature creation time subpac', 'bad magic'];

function ignoredError(error) {
  return expected.some(message => error.message.includes(message) || error.name === 'UnsupportedError' || error.name !== 'TypeError');
}

/**
 * @param { Buffer } inputData
 */
export function fuzz (inputData) {
  const binaryMessage = new Uint8Array(inputData);
  binaryMessage[0] |= 0x80;
  return readMessage({ binaryMessage })
    .catch(error => {
      if (error.message && !ignoredError(error)) {
        throw error;
      }
    });
}

