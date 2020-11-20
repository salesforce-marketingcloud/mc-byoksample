/**
 * Generate and wrap keys using an HSM via PKCS#11 for use with Marketing Cloud BYOK
 * Note: The HSM session is opened in read-only mode and may not save keys to the HSM.
 *
 * This script is only intended as an example for key wrapping using the appropriate
 * mechanisms. It is not intended for use in a production environment as-is.
 *
 */

const fs = require('fs');
const forge = require('node-forge');
const graphene = require('graphene-pk11');

const INPUT_CERT_FILE = 'salesforce_rsa_pub';
const OUTPUT_AES_FILE = 'oaep_wrapped_intermediate_aes_key.b64';
const OUTPUT_RSA_FILE = 'aes_wrapped_user_rsa_key.b64';

const HSM_PKCS11_LIB_FILE = 'C:/SoftHSM2/lib/softhsm2-x64.dll';
const HSM_PKCS11_LIB_NAME = 'SoftHSM';
const HSM_LOGIN_PIN = '1234';

const UNSAFE_USE_LOCAL_OAEP = false; // perform OAEP key wrapping locally instead of on the HSM
const USE_SAFENET = false; // use SafeNet Luna HSM 'CK_AES_KWP' mechanism for AES KEY WRAP PAD

/**
 * Generate AES Intermediate Key in HSM (this key is only used 1 time to wrap the RSA key)
 * @param {} session - PKCS11 session
 */
function hsmCreateAesKey(session) {
  return session.generateKey(graphene.KeyGenMechanism.AES, {
    valueLen: 32,
    keyType: graphene.KeyType.AES,
    extractable: true,
    wrap: true,
    encrypt: true,
  });
}

/**
 * Generate the RSA key in HSM (this is the customer key for BYOK)
 * @param {} session - PKCS11 session
 * @param {} label - HSM key label
 * @param {} id - HSM key id
 */
function hsmCreateRsaKey(session, label, id) {
  return session.generateKeyPair(
    graphene.KeyGenMechanism.RSA,
    {
      keyType: graphene.KeyType.RSA,
      modulusBits: 2048,
      publicExponent: Buffer.from([3]),
      token: true,
      label,
      id,
    },
    {
      keyType: graphene.KeyType.RSA,
      extractable: true,
      token: true,
      label,
      id,
    },
  );
}

/**
 * Wrap the RSA key using the HSM
 * @param {} session - PKCS11 session
 * @param {} aesKey - the AES key to use for wrapping
 * @param {} rsaKey - the RSA to be wrapped
 */
function hsmWrapRsaKey(session, aesKey, rsaKey) {
  return session.wrapKey(
    !USE_SAFENET ? graphene.MechanismEnum.AES_KEY_WRAP_PAD : 'AES_KWP',
    aesKey,
    rsaKey.privateKey,
  );
}

/**
 * Wrap the AES key using the HSM
 * @param {} session - PKCS11 session
 * @param {} rsaPublicKey - the RSA key to use for wrapping (salesforce key)
 * @param {} aesKey - the AES key to be wrapped
 */
function hsmWrapAesKey(session, rsaPublicKey, aesKey) {
  const objectTemplate = {
    class: graphene.ObjectClass.PUBLIC_KEY,
    keyType: graphene.KeyType.RSA,
    modulus: Buffer.from(rsaPublicKey.n.toByteArray()),
    publicExponent: Buffer.from(rsaPublicKey.e.toByteArray()),
    wrap: true,
    encrypt: true,
  };

  const publicKey = session.create(objectTemplate).toType();

  const wrappingAlgorithm = {
    name: 'RSA_PKCS_OAEP',
    params: new graphene.RsaOaepParams(
      graphene.MechanismEnum.SHA256,
      graphene.RsaMgf.MGF1_SHA256,
    ),
  };

  try {
    return session.wrapKey(wrappingAlgorithm, publicKey, aesKey);
  } catch (err) {
    if (!UNSAFE_USE_LOCAL_OAEP) {
      console.error(`Error wrapping key using RSA_PKCS_OAEP (The HSM may not support OAEP with SHA256): ${err}`);
      throw err;
    }

    return undefined;
  }
}

/**
 * Wrap the AES key locally
 * @param {} rsaPublicKey - the RSA key to use for wrapping (salesforce key)
 * @param {} aesKey - the AES key to be wrapped
 */
function localWrapAesKey(rsaPublicKey, aesKey) {
  console.warn('WARNING: Using local computer to wrap the AES key');
  const aesKeyValue = Buffer.from(aesKey.getAttribute('value')).toString('binary');

  const encrypted = rsaPublicKey.encrypt(
    aesKeyValue,
    'RSA-OAEP',
    {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create(),
      },
    },
  );

  // convert to buffer
  return Buffer.from(encrypted, 'binary');
}

/**
 * Save wrapped key as base64 to disk
 * @param {*} filename - filename
 * @param {*} data - buffer with key data
 */
function saveWrappedKey(filename, data) {
  // convert data (buffer) to base64
  const encoded = data.toString('base64');
  fs.writeFileSync(filename, encoded);

  console.log(`Saved file ${filename}`);
}

// Initialize
const mod = graphene.Module.load(HSM_PKCS11_LIB_FILE, HSM_PKCS11_LIB_NAME);
mod.initialize();
const slot = mod.getSlots(0);
// eslint-disable-next-line no-bitwise
if (!(slot.flags & graphene.SlotFlag.TOKEN_PRESENT)) {
  console.error('Slot is not initialized');
  mod.finalize();
  throw new Error();
}
const session = slot.open(graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION);
session.login(HSM_LOGIN_PIN);

if (USE_SAFENET) {
  graphene.Mechanism.vendor('AES_KWP', 2147484017); // SafeNet CKM_AES_KWP
}

// Read the salesforce public cert file (RSA 4096)
const salesforceKey = forge.pki.publicKeyFromPem(fs.readFileSync(INPUT_CERT_FILE, 'utf8'));

// Generate AES Intermediate Key (AES 256)
const aesKey = hsmCreateAesKey(session);

// Wrap the AES intermediate key with the Salesforce Wrapping Public Key (RSA OAEP SHA 256 MGF1)
const wrappedAesKey = hsmWrapAesKey(session, salesforceKey, aesKey)
  || (UNSAFE_USE_LOCAL_OAEP && localWrapAesKey(salesforceKey, aesKey));

// Generate RSA key (RSA 2048)
const label = `MC_${Date.now()}`;
const id = Buffer.from(label);
console.log(`Creating RSA private/public key object in HSM: label = ${label}, id = ${id}`);
const rsaKey = hsmCreateRsaKey(session, label, id);

// Wrap the RSA private key with the Intermediate Key (AES WRAP PAD)
const wrappedRsaKey = hsmWrapRsaKey(session, aesKey, rsaKey);

// Save the wrapped keys to disk encoded in base64
saveWrappedKey(OUTPUT_RSA_FILE, wrappedRsaKey);
saveWrappedKey(OUTPUT_AES_FILE, wrappedAesKey);

// Clean-up
session.destroy(aesKey);
session.logout();
session.close();
mod.finalize();
