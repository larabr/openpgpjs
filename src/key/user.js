/**
 * @module key/User
 * @private
 */

import enums from '../enums';
import util from '../util';
import { PacketList } from '../packet';
import { mergeSignatures, isDataRevoked, createSignaturePacket } from './helper';

/**
 * Class that represents an user ID or attribute packet and the relevant signatures.
 */
class User {
  constructor(userPacket) {
    this.userID = userPacket.constructor.tag === enums.packet.userID ? userPacket : null;
    this.userAttribute = userPacket.constructor.tag === enums.packet.userAttribute ? userPacket : null;
    this.selfCertifications = [];
    this.otherCertifications = [];
    this.revocationSignatures = [];
  }

  /**
   * Transforms structured user data to packetlist
   * @returns {PacketList}
   */
  toPacketList() {
    const packetlist = new PacketList();
    packetlist.push(this.userID || this.userAttribute);
    packetlist.push(...this.revocationSignatures);
    packetlist.push(...this.selfCertifications);
    packetlist.push(...this.otherCertifications);
    return packetlist;
  }

  /**
   * Signs user
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket}          primaryKey  The primary key packet
   * @param {Array<Key>} privateKeys - Decrypted private keys for signing
   * @param {Date} date - Date to overwrite creation date of the signature
   * @param {Object} config - Full configuration
   * @returns {Promise<Key>} New user with new certificate signatures.
   * @async
   */
  async sign(primaryKey, privateKeys, date, config) {
    const dataToSign = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    const user = new User(dataToSign.userID || dataToSign.userAttribute);
    user.otherCertifications = await Promise.all(privateKeys.map(async function(privateKey) {
      if (privateKey.isPublic()) {
        throw new Error('Need private key for signing');
      }
      if (privateKey.hasSameFingerprintAs(primaryKey)) {
        throw new Error('Not implemented for self signing');
      }
      const signingKey = await privateKey.getSigningKey(undefined, date, undefined, config);
      return createSignaturePacket(dataToSign, privateKey, signingKey.keyPacket, {
        // Most OpenPGP implementations use generic certification (0x10)
        signatureType: enums.signature.certGeneric,
        keyFlags: [enums.keyFlags.certifyKeys | enums.keyFlags.signData]
      }, date, undefined, undefined, config);
    }));
    await user.update(this, primaryKey, date, config);
    return user;
  }

  /**
   * Checks if a given certificate of the user is revoked
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey    The primary key packet
   * @param {SignaturePacket} certificate - The certificate to verify
   * @param  {PublicSubkeyPacket|
   *          SecretSubkeyPacket|
   *          PublicKeyPacket|
   *          SecretKeyPacket} key, optional The key to verify the signature
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<Boolean>} True if the certificate is revoked.
   * @async
   */
  async isRevoked(primaryKey, certificate, key, date = new Date(), config) {
    return isDataRevoked(
      primaryKey, enums.signature.certRevocation, {
        key: primaryKey,
        userID: this.userID,
        userAttribute: this.userAttribute
      }, this.revocationSignatures, certificate, key, date, config
    );
  }

  /**
   * Verifies the user certificate.
   * @param {SignaturePacket} certificate - A certificate of this user
   * @param {Array<PublicKey>} verificationKeys - Array of keys to verify certificate signatures
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<true|null>} true if the certificate could be verified, or null if the verification keys do not correspond to the certificate
   * @throws if the user certificate is invalid.
   * @async
   */
  async verifyCertificate(primaryKey, certificate, verificationKeys, date = new Date(), config) {
    const that = this;
    const keyID = certificate.issuerKeyID;
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    const issuerKeys = verificationKeys.filter(key => key.getKeys(keyID).length > 0);
    if (issuerKeys.length === 0) {
      return null;
    }
    await Promise.all(issuerKeys.map(async key => {
      const signingKey = await key.getSigningKey(keyID, certificate.created, undefined, config);
      if (certificate.revoked || await that.isRevoked(primaryKey, certificate, signingKey.keyPacket, date, config)) {
        throw new Error('User certificate is revoked');
      }
      try {
        await certificate.verify(signingKey.keyPacket, enums.signature.certGeneric, dataToVerify, date, undefined, config);
      } catch (e) {
        throw util.wrapError('User certificate is invalid', e);
      }
    }));
    return true;
  }

  /**
   * Verifies all user certificates
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey The primary key packet
   * @param {Array<Key>} keys - Array of keys to verify certificate signatures
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<Array<{
   *   keyID: module:type/keyid~KeyID,
   *   valid: Boolean
   * }>>} List of signer's keyID and validity of signature
   * @async
   */
  async verifyAllCertifications(primaryKey, keys, date = new Date(), config) {
    const that = this;
    const certifications = this.selfCertifications.concat(this.otherCertifications);
    return Promise.all(certifications.map(async function(certification) {
      return {
        keyID: certification.issuerKeyID,
        valid: await that.verifyCertificate(primaryKey, certification, keys, date, config).catch(() => false)
      };
    }));
  }

  /**
   * Verify User. Checks for existence of self signatures, revocation signatures
   * and validity of self signature.
   * @param  {SecretKeyPacket|
   *          PublicKeyPacket} primaryKey The primary key packet
   * @param {Date} date - Use the given date instead of the current time
   * @param {Object} config - Full configuration
   * @returns {Promise<true>} Status of user.
   * @throws {Error} if there are no valid self signatures.
   * @async
   */
  async verify(primaryKey, date = new Date(), config) {
    if (!this.selfCertifications.length) {
      throw new Error('No self-certifications');
    }
    const that = this;
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    // TODO replace when Promise.some or Promise.any are implemented
    let exception;
    for (let i = this.selfCertifications.length - 1; i >= 0; i--) {
      try {
        const selfCertification = this.selfCertifications[i];
        if (selfCertification.revoked || await that.isRevoked(primaryKey, selfCertification, undefined, date, config)) {
          throw new Error('Self-certification is revoked');
        }
        try {
          await selfCertification.verify(primaryKey, enums.signature.certGeneric, dataToVerify, date, undefined, config);
        } catch (e) {
          throw util.wrapError('Self-certification is invalid', e);
        }
        return true;
      } catch (e) {
        exception = e;
      }
    }
    throw exception;
  }

  /**
   * Update user with new components from specified user
   * @param {User} user - Source user to merge
   * @param  {SecretKeyPacket|
   *          SecretSubkeyPacket} primaryKey primary key used for validation
   * @param {Date} date - Date to verify the validity of signatures
   * @param {Object} config - Full configuration
   * @returns {Promise<undefined>}
   * @async
   */
  async update(user, primaryKey, date, config) {
    const dataToVerify = {
      userID: this.userID,
      userAttribute: this.userAttribute,
      key: primaryKey
    };
    // self signatures
    await mergeSignatures(user, this, 'selfCertifications', date, async function(srcSelfSig) {
      try {
        await srcSelfSig.verify(primaryKey, enums.signature.certGeneric, dataToVerify, date, false, config);
        return true;
      } catch (e) {
        return false;
      }
    });
    // other signatures
    await mergeSignatures(user, this, 'otherCertifications', date);
    // revocation signatures
    await mergeSignatures(user, this, 'revocationSignatures', date, function(srcRevSig) {
      return isDataRevoked(primaryKey, enums.signature.certRevocation, dataToVerify, [srcRevSig], undefined, undefined, date, config);
    });
  }
}

export default User;
