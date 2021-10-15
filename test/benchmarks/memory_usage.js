/* eslint-disable no-console */
const assert = require('assert');
const stream = require('@openpgp/web-stream-tools');
const path = require('path');
const { writeFileSync, unlinkSync } = require('fs');
const { fork } = require('child_process');
const openpgp = require('../..');

/**
 * Benchmark max memory usage recorded during execution of the given function.
 * This spawns a new v8 instance and runs the code there in isolation, to avoid interference between tests.
 * @param {Funtion} function to benchmark (can be async)
 * @returns {NodeJS.MemoryUsage} memory usage snapshot with max RSS (sizes in bytes)
 */
const benchmark = async function(fn) {
  const tmpFileName = path.join(__dirname, 'tmp.js');
  // the code to execute must be written to a file
  writeFileSync(tmpFileName, `
const assert = require('assert');
const stream = require('@openpgp/web-stream-tools');
const openpgp = require('../..');
let maxMemoryComsumption;
let activeSampling = false;

function sampleOnce() {
  const memUsage = process.memoryUsage();
  if (!maxMemoryComsumption || memUsage.rss > maxMemoryComsumption.rss) {
    maxMemoryComsumption = memUsage;
  }
}

function samplePeriodically() {
  setImmediate(() => {
    sampleOnce();
    activeSampling && samplePeriodically();
  });
}

// main body
(async () => {
  maxMemoryComsumption = null;
  activeSampling = true;
  samplePeriodically();
  await (${fn.toString()})();
  // setImmediate is run at the end of the event loop, so we need to manually collect the latest sample
  sampleOnce();
  process.send(maxMemoryComsumption);
  process.exit(); // child process doesn't exit otherwise
})();
`);

  const maxMemoryComsumption = await new Promise((resolve, reject) => {
    const child = fork(tmpFileName);
    child.on('message', function (message) {
      resolve(message);
    });
    child.on('error', function (err) {
      reject(err);
    });
  });

  unlinkSync(tmpFileName);
  return maxMemoryComsumption;
};

const onError = err => {
  console.error('The memory benchmark tests failed by throwing the following error:');
  console.error(err);
  // eslint-disable-next-line no-process-exit
  process.exit(1);
};

class MemoryBenchamrkSuite {
  constructor() {
    this.tests = [];
  }

  add(name, fn) {
    this.tests.push({ name, fn });
  }

  async run() {
    const stats = []; // the size of this data should be negligible compared to the tests
    for (const { name, fn } of this.tests) {
      const memoryUsage = await benchmark(fn).catch(onError);
      // convert values to MB
      Object.entries(memoryUsage).forEach(([name, value]) => {
        memoryUsage[name] = (value / 1024 / 1024).toFixed(2);
      });
      const { rss, ...usageDetails } = memoryUsage;
      // raw entry format accepted by github-action-pull-request-benchmark
      stats.push({
        name,
        value: rss,
        range: Object.entries(usageDetails).map(([name, value]) => `${name}: ${value}`).join(', '),
        unit: 'MB',
        biggerIsBetter: false
      });
    }
    return stats;
  }
}

/**
 * Memory usage tests.
 * All the necessary variables must be declared inside the test function.
 */
(async () => {
  const suite = new MemoryBenchamrkSuite();

  suite.add('empty test (baseline)', () => {});

  suite.add('openpgp.encrypt/decrypt (CFB, binary)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: new Uint8Array(1000000).fill(1) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: 'a'.repeat(10000000 / 2) }); // two bytes per character

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, binary)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: new Uint8Array(1000000).fill(1) });

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, text)', async () => {
    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: 'a'.repeat(10000000 / 2) }); // two bytes per character

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  // streaming tests
  suite.add('openpgp.encrypt/decrypt (CFB, binary, with streaming)', async () => {
    await stream.loadStreamsPonyfill();

    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: stream.toStream(new Uint8Array(1000000).fill(1)) });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    await stream.readToEnd(decryptedData);
  });

  suite.add('openpgp.encrypt/decrypt (CFB, text, with streaming)', async () => {
    await stream.loadStreamsPonyfill();

    const passwords = 'password';
    const config = { aeadProtect: false, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: stream.toStream('a'.repeat(10000000 / 2)) });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, passwords, config });
    await stream.readToEnd(decryptedData);
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, binary, with streaming)', async () => {
    await stream.loadStreamsPonyfill();

    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ binary: stream.toStream(new Uint8Array(1000000).fill(1)) });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  suite.add('openpgp.encrypt/decrypt (AEAD, text, with streaming)', async () => {
    await stream.loadStreamsPonyfill();

    const passwords = 'password';
    const config = { aeadProtect: true, preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed };
    const plaintextMessage = await openpgp.createMessage({ text: stream.toStream('a'.repeat(10000000 / 2)) });
    assert(plaintextMessage.fromStream);

    const armoredEncryptedMessage = await openpgp.encrypt({ message: plaintextMessage, passwords, config });
    const encryptedMessage = await openpgp.readMessage({ armoredMessage: armoredEncryptedMessage });
    assert.ok(encryptedMessage.packets[1] instanceof openpgp.AEADEncryptedDataPacket);
    await openpgp.decrypt({ message: encryptedMessage, passwords, config });
  });

  const stats = await suite.run();
  // Print JSON stats to stdout
  console.log(JSON.stringify(stats, null, 4));
})();
