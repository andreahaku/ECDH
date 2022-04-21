/* eslint-disable import/no-nodejs-modules */
const crypto = require("crypto");

/**
 * Class that exposes methods to generate and compute
 * Elliptic Curve Diffie-Hellman (ECDH) for key exchange
 *
 * It also exposes encryption/decryption methods that are used
 * by the WebRTC communication layer to encrypt/decrypt in/out data
 * The encryption/decryption is made using a symmetric key coming from the ECDH key exchange
 */
class ECDH {
  ecdh;
  secretKey;

  constructor() {
    this.ecdh = null; // ecdh instance
    this.secretKey = null; // symmetric secret key to use for webrtc encryption/decryption
  }

  /**
   * Creates ECDH instance
   *
   * @returns - ECDH instance
   */
  generateECDH = () => {
    this.ecdh = crypto.createECDH("secp256k1");
    this.ecdh.generateKeys();
  };

  /**
   * Generates ECDH key pair and
   * returns public key
   *
   * @returns - public key in base64 format
   */
  getPublicKey = () => this.ecdh.getPublicKey().toString("base64");

  /**
   * Computes the secret key by using the received public key
   *
   * @param {string} otherPublicKey - ECDH key received in base64 format
   * @returns - secret key in hex
   */
  computeECDHSecret = (otherPublicKey) => {
    this.secretKey = this.ecdh.computeSecret(otherPublicKey, "base64", "hex");
  };

  // /**
  //  * Encrypts a data message using the secret key
  //  *
  //  * @param {string} data - data string to be encrypted
  //  * @returns - encrypted string in base64
  //  */
  // encrypt = (data) => {
  //   const cipher = crypto.createCipher("aes-256-cbc", this.secretKey);

  //   let encryptedData = cipher.update(data, "utf8", "base64");
  //   encryptedData += cipher.final("base64");

  //   return encryptedData;
  // };

  /**
   * Encrypts a data message using the secret key
   * with Authentication and IV (initialisation vector)
   *
   * @param {string} data - data string to be encrypted
   * @returns - encrypted string in base64
   */
  encryptAuthIV = (data) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      "aes-256-gcm",
      Buffer.from(this.secretKey, "hex"),
      iv
    );

    let encryptedData = cipher.update(data, "utf8", "hex");
    encryptedData += cipher.final("hex");

    const authTag = cipher.getAuthTag().toString("hex");
    console.log("AUTHTAG:", authTag);

    const payload = iv.toString("hex") + encryptedData + authTag;
    const payload64 = Buffer.from(payload, "hex").toString("base64");

    return payload64;
  };

  // /**
  //  * Decrypts a data message using the secret key
  //  *
  //  * @param {string} encryptedData - base64 data string to be decrypted
  //  * @returns - decrypted data
  //  */
  // decrypt = (encryptedData) => {
  //   const decipher = crypto.createDecipher("aes-256-cbc", this.secretKey);

  //   let decryptedData = decipher.update(encryptedData, "base64", "utf8");
  //   decryptedData += decipher.final("utf8");

  //   return decryptedData;
  // };

  /**
   * Decrypts a data message using the secret key
   * with Authentication and IV (initialisation vector)
   *
   * @param {string} encryptedData - base64 data string to be decrypted
   * @returns - decrypted data || false if error
   */
  decryptAuthIV = (encryptedData) => {
    const payload = Buffer.from(encryptedData, "base64").toString("hex");

    const iv = payload.substr(0, 32);
    const encrypted = payload.substr(32, payload.length - 32 - 32);
    const authTag = payload.substr(payload.length - 32, 32);

    try {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        Buffer.from(this.secretKey, "hex"),
        Buffer.from(iv, "hex")
      );

      decipher.setAuthTag(Buffer.from(authTag, "hex"));

      let decrypted = decipher.update(encrypted, "hex", "utf8");
      decrypted += decipher.final("utf8");

      return decrypted;
    } catch (error) {
      console.warn(error.message);
      return false;
    }
  };
}

const AliceECDH = new ECDH();
const BobECDH = new ECDH();
const CharlesECDH = new ECDH();

AliceECDH.generateECDH();
BobECDH.generateECDH();
CharlesECDH.generateECDH();

let AlicePublicKey;
let BobPublicKey;
let CharlesPublicKey;

let AliceSecretKey;
let BobSecretKey;
let CharlesSecretKey;

AlicePublicKey = AliceECDH.getPublicKey();
BobPublicKey = BobECDH.getPublicKey();
CharlesPublicKey = CharlesECDH.getPublicKey();

console.log("ALICE Pkey:", AlicePublicKey);
console.log("BOB Pkey:", BobPublicKey);
console.log("CHARLES Pkey:", CharlesPublicKey);
console.log();

AliceECDH.computeECDHSecret(BobPublicKey);
BobECDH.computeECDHSecret(AlicePublicKey);
CharlesECDH.computeECDHSecret(AlicePublicKey);
CharlesECDH.computeECDHSecret(BobPublicKey);

console.log("ALICE - BOB:", AliceECDH.secretKey, AliceECDH.secretKey.length);
console.log("BOB - ALICE:", BobECDH.secretKey);
console.log();

console.log("CHARLES - ALICE:", CharlesECDH.secretKey);
console.log("CHARLES - BOB:", CharlesECDH.secretKey);
console.log();

const message = "This is a test message";
const message2 = "This is another test message";

// const encryptedMessage = BobECDH.encrypt(message);
// const decryptedMessage = AliceECDH.decrypt(encryptedMessage);
// console.log("MESSAGE:", decryptedMessage);

console.log("Bob > Alice");
let encryptedMessageIV = BobECDH.encryptAuthIV(message);
let decryptedMessageIV = AliceECDH.decryptAuthIV(encryptedMessageIV);
console.log("MESSAGE IV:", decryptedMessageIV, "\n");

console.log("Alice > Bob");
encryptedMessageIV = AliceECDH.encryptAuthIV(message2);
decryptedMessageIV = BobECDH.decryptAuthIV(encryptedMessageIV);
console.log("MESSAGE IV:", decryptedMessageIV, "\n");

console.log("Charles > Alice");
encryptedMessageIV = CharlesECDH.encryptAuthIV(message2);
decryptedMessageIV = AliceECDH.decryptAuthIV(encryptedMessageIV);
console.log("MESSAGE IV:", decryptedMessageIV, "\n");
