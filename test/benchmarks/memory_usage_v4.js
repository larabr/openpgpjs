/* eslint-disable no-console */
const assert = require('assert');
const stream = require('@openpgp/web-stream-tools');
const path = require('path');
const { writeFileSync, unlinkSync, createReadStream } = require('fs');
const { fork } = require('child_process');
const openpgp = require('./openpgp_v4');

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
const { createReadStream } = require('fs');
const openpgp = require('./openpgp_v4');
const stream = openpgp.stream;
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
    const stats = [];
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

  suite.add('openpgp.decrypt-verify (CFB, large, with streaming)', async () => {
    const { keys: privateKeys } = await openpgp.key.readArmored(`-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYXFgahYJKwYBBAHaRw8BAQdAHzCRqig6SFJJL0ZDoeAlsSQbOp/Ucc4A
+IX3n7uJBlEAAQCrsC+V3jXNE0ifW/EQWsSGYwPuyFjYCEtCtI9djHH4Tg++
zQ50ZXN0IDxhQGIuY29tPsKMBBAWCgAdBQJhcWBqBAsJBwgDFQgKBBYAAgEC
GQECGwMCHgEAIQkQWoVKaR/EFAwWIQQNy4WjaTAq9kYmhgZahUppH8QUDKrp
AP9HqbUshf5bSCNUiYMjc8rmyg5zeDiYO1EDqecKw/a5HwEA0tp1so8EZc/x
FxbRy/6BkmiPREJ62ewyC+1lt1NakAXHXQRhcWBqEgorBgEEAZdVAQUBAQdA
O+HoA9+FH7TnWCD2aF/MwlMlJbQvb+BvX3U0gmbV/AcDAQgHAAD/YKh+wGKr
tMaUVq2m+tBn3i8oIJloePGZ9nU3aHxmE6gSOcJ4BBgWCAAJBQJhcWBqAhsM
ACEJEFqFSmkfxBQMFiEEDcuFo2kwKvZGJoYGWoVKaR/EFAzASwEA3ATh53J1
rKdRErUMxSs/foD0JGj08efcDqXDxF58r0UA/088rX4q479fz+BcBMoCSIah
YC+CvDH11xM7cSlqm18N
=/RXG
-----END PGP PRIVATE KEY BLOCK-----`);
    const publicKeys = privateKeys;
    const readableStream = createReadStream('./test/benchmarks/enc.zip.pgp');
    const encryptedMessage = await openpgp.message.read(readableStream);
    // assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData, signatures: [sigInfo] } = await openpgp.decrypt({ message: encryptedMessage, privateKeys, publicKeys, format: 'binary' });

    console.log('start reading');
    await stream.readToEnd(decryptedData);
    await sigInfo.verified;
  });

  suite.add('openpgp.decrypt (CFB, large, with streaming)', async () => {
    const { keys: privateKeys } = await openpgp.key.readArmored(`-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYXFgahYJKwYBBAHaRw8BAQdAHzCRqig6SFJJL0ZDoeAlsSQbOp/Ucc4A
+IX3n7uJBlEAAQCrsC+V3jXNE0ifW/EQWsSGYwPuyFjYCEtCtI9djHH4Tg++
zQ50ZXN0IDxhQGIuY29tPsKMBBAWCgAdBQJhcWBqBAsJBwgDFQgKBBYAAgEC
GQECGwMCHgEAIQkQWoVKaR/EFAwWIQQNy4WjaTAq9kYmhgZahUppH8QUDKrp
AP9HqbUshf5bSCNUiYMjc8rmyg5zeDiYO1EDqecKw/a5HwEA0tp1so8EZc/x
FxbRy/6BkmiPREJ62ewyC+1lt1NakAXHXQRhcWBqEgorBgEEAZdVAQUBAQdA
O+HoA9+FH7TnWCD2aF/MwlMlJbQvb+BvX3U0gmbV/AcDAQgHAAD/YKh+wGKr
tMaUVq2m+tBn3i8oIJloePGZ9nU3aHxmE6gSOcJ4BBgWCAAJBQJhcWBqAhsM
ACEJEFqFSmkfxBQMFiEEDcuFo2kwKvZGJoYGWoVKaR/EFAzASwEA3ATh53J1
rKdRErUMxSs/foD0JGj08efcDqXDxF58r0UA/088rX4q479fz+BcBMoCSIah
YC+CvDH11xM7cSlqm18N
=/RXG
-----END PGP PRIVATE KEY BLOCK-----`);
    const publicKeys = privateKeys;
    const readableStream = createReadStream('./test/benchmarks/enc.zip.unsigned.pgp');
    const encryptedMessage = await openpgp.message.read(readableStream);
    // assert.ok(encryptedMessage.packets[1] instanceof openpgp.SymEncryptedIntegrityProtectedDataPacket);
    const { data: decryptedData } = await openpgp.decrypt({ message: encryptedMessage, privateKeys, publicKeys, format: 'binary' });

    console.log('start reading');
    await stream.readToEnd(decryptedData);
  });

  const stats = await suite.run();
  // Print JSON stats to stdout
  console.log(JSON.stringify(stats, null, 4));
})();
