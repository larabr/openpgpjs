import util from '../../src/util.js';

const elliptic_data = {
  key_data: {
    p256: {
      priv: new Uint8Array([
        0x2B, 0x48, 0x2B, 0xE9, 0x88, 0x74, 0xE9, 0x49,
        0x1F, 0x89, 0xCC, 0xFF, 0x0A, 0x26, 0x05, 0xA2,
        0x3C, 0x2A, 0x35, 0x25, 0x26, 0x11, 0xD7, 0xEA,
        0xA1, 0xED, 0x29, 0x95, 0xB5, 0xE1, 0x5F, 0x1D
      ]),
      pub: new Uint8Array([
        0x04,
        0x80, 0x2C, 0x40, 0x76, 0x31, 0x20, 0xB6, 0x9B,
        0x48, 0x3B, 0x05, 0xEB, 0x6C, 0x1E, 0x3F, 0x49,
        0x84, 0xF7, 0xD2, 0xAD, 0x16, 0xA1, 0x6F, 0x62,
        0xFD, 0xCA, 0xEC, 0xB4, 0xA0, 0xBD, 0x4C, 0x1A,
        0x6F, 0xAA, 0xE7, 0xFD, 0xC4, 0x7D, 0x89, 0xCC,
        0x06, 0xCA, 0xFE, 0xAE, 0xCD, 0x0E, 0x9E, 0x62,
        0x57, 0xA4, 0xC3, 0xE7, 0x5E, 0x69, 0x10, 0xEE,
        0x67, 0xC2, 0x09, 0xF9, 0xEF, 0xE7, 0x9E, 0x56
      ])
    },
    p384: {
      priv: new Uint8Array([
        0xB5, 0x38, 0xDA, 0xF3, 0x77, 0x58, 0x3F, 0x94,
        0x5B, 0xC2, 0xCA, 0xC6, 0xA9, 0xFC, 0xAA, 0x3F,
        0x97, 0xB0, 0x54, 0x26, 0x10, 0xB4, 0xEC, 0x2A,
        0xA7, 0xC1, 0xA3, 0x4B, 0xC0, 0xBD, 0xFE, 0x3E,
        0xF1, 0xBE, 0x76, 0xCB, 0xE8, 0xAB, 0x3B, 0xBD,
        0xB6, 0x84, 0xC7, 0x8B, 0x91, 0x2F, 0x76, 0x8B
      ]),
      pub: new Uint8Array([
        0x04,
        0x44, 0x83, 0xA0, 0x3E, 0x5B, 0x0A, 0x0D, 0x9B,
        0xA0, 0x06, 0xDF, 0x38, 0xC7, 0x64, 0xCD, 0x62,
        0x7D, 0x5E, 0x3D, 0x3B, 0x50, 0xF5, 0x06, 0xC7,
        0xF7, 0x9B, 0xF0, 0xDE, 0xB1, 0x0C, 0x64, 0x74,
        0x0D, 0x03, 0x67, 0x24, 0xA0, 0xFF, 0xD1, 0x3D,
        0x03, 0x96, 0x48, 0xE7, 0x73, 0x5E, 0xF1, 0xC0,
        0x62, 0xCC, 0x33, 0x5A, 0x2A, 0x66, 0xA7, 0xAB,
        0xCA, 0x77, 0x52, 0xB8, 0xCD, 0xB5, 0x91, 0x16,
        0xAF, 0x42, 0xBB, 0x79, 0x0A, 0x59, 0x51, 0x68,
        0x8E, 0xEA, 0x32, 0x7D, 0x4A, 0x4A, 0xBB, 0x26,
        0x13, 0xFB, 0x95, 0xC0, 0xB1, 0xA4, 0x54, 0xCA,
        0xFA, 0x85, 0x8A, 0x4B, 0x58, 0x7C, 0x61, 0x39
      ])
    },
    p521: {
      priv: new Uint8Array([
        0x00, 0xBB, 0x35, 0x27, 0xBC, 0xD6, 0x7E, 0x35,
        0xD5, 0xC5, 0x99, 0xC9, 0xB4, 0x6C, 0xEE, 0xDE,
        0x79, 0x2D, 0x77, 0xBD, 0x0A, 0x08, 0x9A, 0xC2,
        0x21, 0xF8, 0x35, 0x1C, 0x49, 0x5C, 0x40, 0x11,
        0xAC, 0x95, 0x2A, 0xEE, 0x91, 0x3A, 0x60, 0x5A,
        0x25, 0x5A, 0x95, 0x38, 0xDC, 0xEB, 0x59, 0x8E,
        0x33, 0xAD, 0xC0, 0x0B, 0x56, 0xB1, 0x06, 0x8C,
        0x57, 0x48, 0xA3, 0x73, 0xDB, 0xE0, 0x19, 0x50,
        0x2E, 0x79
      ]),
      pub: new Uint8Array([
        0x04,
        0x01, 0x0D, 0xD5, 0xCA, 0xD8, 0xB0, 0xEF, 0x9F,
        0x2B, 0x7E, 0x58, 0x99, 0xDE, 0x05, 0xF6, 0xF6,
        0x64, 0x6B, 0xCD, 0x59, 0x2E, 0x39, 0xB8, 0x82,
        0xB3, 0x13, 0xE6, 0x7D, 0x50, 0x85, 0xC3, 0xFA,
        0x93, 0xA5, 0x3F, 0x92, 0x85, 0x42, 0x36, 0xC0,
        0x83, 0xC9, 0xA4, 0x38, 0xB3, 0xD1, 0x99, 0xDA,
        0xE1, 0x02, 0x37, 0x7A, 0x3A, 0xC2, 0xB4, 0x55,
        0xEC, 0x1C, 0x0F, 0x00, 0x97, 0xFC, 0x75, 0x93,
        0xFE, 0x87, 0x00, 0x7D, 0xBE, 0x1A, 0xF5, 0xF9,
        0x57, 0x5C, 0xF2, 0x50, 0x2D, 0x14, 0x32, 0xEE,
        0x9B, 0xBE, 0xB3, 0x0E, 0x12, 0x2F, 0xF8, 0x85,
        0x11, 0x1A, 0x4F, 0x88, 0x50, 0xA4, 0xDB, 0x37,
        0xA6, 0x53, 0x5C, 0xB7, 0x87, 0xA6, 0x06, 0x21,
        0x15, 0xCC, 0x12, 0xC0, 0x1C, 0x83, 0x6F, 0x7B,
        0x5A, 0x8A, 0x36, 0x4E, 0x46, 0x9E, 0x54, 0x3F,
        0xE2, 0xF7, 0xED, 0x63, 0xC9, 0x92, 0xA4, 0x38,
        0x2B, 0x9C, 0xE2, 0xB7
      ])
    },
    secp256k1: {
      priv: new Uint8Array([
        0x9E, 0xB0, 0x30, 0xD6, 0xE1, 0xCE, 0xAA, 0x0B,
        0x7B, 0x8F, 0xDE, 0x5D, 0x91, 0x4D, 0xDC, 0xA0,
        0xAD, 0x05, 0xAB, 0x8F, 0x87, 0x9B, 0x57, 0x48,
        0xAE, 0x8A, 0xE0, 0xF9, 0x39, 0xBD, 0x24, 0x00
      ]),
      pub: new Uint8Array([
        0x04,
        0xA8, 0x02, 0x35, 0x2C, 0xB7, 0x24, 0x95, 0x51,
        0x0A, 0x65, 0x26, 0x7D, 0xDF, 0xEA, 0x64, 0xB3,
        0xA8, 0xE1, 0x4F, 0xDD, 0x12, 0x84, 0x7E, 0x59,
        0xDB, 0x81, 0x0F, 0x89, 0xED, 0xFB, 0x29, 0xFB,
        0x07, 0x60, 0x29, 0x7D, 0x39, 0x8F, 0xB8, 0x68,
        0xF0, 0xFD, 0xA6, 0x67, 0x83, 0x55, 0x75, 0x7D,
        0xB8, 0xFD, 0x0B, 0xDF, 0x76, 0xCE, 0xBC, 0x95,
        0x4B, 0x92, 0x26, 0xFC, 0xAA, 0x7A, 0x7C, 0x3F
      ])
    },
    brainpoolP256r1: {
      priv: util.hexToUint8Array('8b426897130e1e5e70a4d6320c4002bb1642a5e57ade066e060464137dfd5e05'),
      pub: util.hexToUint8Array('042a43d8cc20e5a3fbd75d3a5a9b17d867bba80f11334d0665f0c641d13460a52aa3373a4ccfaa7d76765a689bd9fe15a4fd107ef1ec9ac980234c31647170c81a')
    },
    brainpoolP384r1: {
      priv: util.hexToUint8Array('7ccc97acdf4b775606c5c994a37a8b28086167046ac0d55664ede4097d8de79dec56e69dfff5776d53fcbd2147bbae9f'),
      pub: util.hexToUint8Array('043809fa0c74ec9817cb73eba67db71e01663528fb9fbe6a123f8339346c37efc9ff7cd116074a80684448e44ee9204c795c88ad634ad272585c0b4e3093b11e6c99a6c0ca9c278f83ef57e2ed802502aee76f4529bcb873eef754bec894a5032f')
    },
    brainpoolP512r1: {
      priv: util.hexToUint8Array('0a32459d1ecf8815397a66f6cdb18692c6f79a3c6059b4c344d0162416c7603a82a9a938568edafb132c7433ffeeab4cf201d9542209eb28070bea56ab6b8938'),
      pub: util.hexToUint8Array('040f64473d9b3597752e3a87095c0b219dd85f56a79c3b2dc8fb2b0c95b60f4be45c41a8a7ea31d60e15fea6275eb7db93856bc2eb30cc8876513335d43812bd2c4e195e05679ac667a2f7fb05c5842779d18fa411500e43e2f291ea8348f061db15382d4db1cfcf106a29f46e1c00e7d63e635c51293f69c0dd4f6a61da589b2a')
    }
  }
};

export default elliptic_data;
