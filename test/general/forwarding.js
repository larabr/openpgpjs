const openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('../..');

const expect = require('chai').expect;

const charlieKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEY/ikABYJKwYBBAHaRw8BAQdAzz/nPfhJnoAYwg43AFYzxX1v6UwGmfN9jPiI
/MOFxFgAAQDTqvO94jZPb9brhpwayNI9QlqqTlvDP6AH8CpXUfoVmxDczRNib2Ig
PGJvYkBwcm90b24ubWU+wooEExYIADwFAmP4pAAJkIdp9lyYAlNMFiEEzW5s1IvY
GXCwcJkZh2n2XJgCU0wCGwMCHgECGQECCwcCFQgCFgACIgEAAPmGAQDxysrSwxQO
27X/eg7xSE5JVXT7bt8cEZOE+iC2IDS02QEA2CvXnZJK4AOmPsFWKzn3HkFxCybc
CefzoJe0Pp4QNwPHcQRj+KQAEgorBgEEAZdVAQUBAQdArC6ijiQbE4ddGzqYHuq3
0rV05YYDP+5GtCecalGVizUX/woJzG7AoQ/hzzDi4rf+is90WDIIeHwAAP9JzVrf
QzMRicxCz1PbXNRW/OwKHg0X0bH3MA5A/j3mcBCrwngEGBYIACoFAmP4pAAJkIdp
9lyYAlNMFiEEzW5s1IvYGXCwcJkZh2n2XJgCU0wCG1AAAN0hAP9kJ/CQDBAwrVj5
92/mkV/4bEWAql/jEEfbBTAGHEb+5wD/ca5jm4FThIaGNO/mLtbkodfR0RTQ5usZ
Xvoo9PdnBQg=
=7A/f
-----END PGP PRIVATE KEY BLOCK-----`;

const fwdCiphertextArmored = `-----BEGIN PGP MESSAGE-----

wV4Dwkk3ytpHrqASAQdAzPWbm24Uj6OYSDaauOuFMRPPLr5zWKXgvC1eHPD78ykw
YkvxNCwD6hfzjLoASVv9jhHJoXY+Pag6QHvoFuMn+hdG90yFh5HMFyileY/CTrT7
0kcBAPalcAq/OH/pBtIhGT/TKS88IIkz2aSukjbQRf+JNyh7bF+uXVDGmD8zOGa8
mM9TmGOf8Vi3sjgVAQ5rZQzh36HrBDloBA==
=PotS
-----END PGP MESSAGE-----`;

module.exports = () => describe('Forwarding', function() {
  it('can decrypt forwarded ciphertext', async function() {
    const charlieKey = await openpgp.readKey({ armoredKey: charlieKeyArmored });
    const msg = await openpgp.readMessage({ armoredMessage: fwdCiphertextArmored });
    const result = await openpgp.decrypt({ decryptionKeys: charlieKey, message: msg });

    expect(result).to.exist;
    expect(result.data).to.equal('Hello Bob, hello world');
  });
});
