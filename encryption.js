
// ------------------------------- Key Creation -----------------------------
/**
 * @brief Generates a key pair for asymmetric encryption using RSA-OAEP
 * @returns key pair object with public and private keys in base64 format
 */
async function generateAsemmetricKeyPair() {
    // Mozilla's web docs : https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
    // Generate RSA key pair
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );

    // Export the public key, spki format is common for public keys
    const exportedPublicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = this.arrayBufferToBase64(exportedPublicKey);

    // Export the private key, pkcs8 format is common for private keys
    const exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateKeyBase64 = this.arrayBufferToBase64(exportedPrivateKey);

    return { publicKey: publicKeyBase64, privateKey: privateKeyBase64 };
}

/**
 * @brief Generates a symmetric key with a password using PBKDF2
 * @param {string} password password to generate the symmetric key with PBKDF2
 * @returns symmetric key and salt object
 */
async function generateSymmetricKeyWithPassword(password) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iterations = 1000000;
    const hash = "SHA-256";
    const keyLength = 256;
    const passwordBuffer = new TextEncoder().encode(password);
    // PBKDF2 : Password-Based Key Derivation Function 2
    const key = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false, // This makes the key not extractable, meaning it can't be exported.
        ["deriveBits", "deriveKey"]
    );

    const symmetricKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: hash
        },
        key,
        { name: "AES-GCM", length: keyLength },
        true,
        ["encrypt", "decrypt"]
    );
    // convert the salt to base64
    const saltBase64 = arrayBufferToBase64(salt);

    return { symmetricKey: symmetricKey, salt: saltBase64 };
}

// recreate symmetric key from password, salt
async function recreateSymmetricKeyWithPassword(password, saltBase64) {
    const salt = base64ToArrayBuffer(saltBase64);
    const iterations = 1000000;
    const hash = "SHA-256";
    const keyLength = 256;
    const passwordBuffer = new TextEncoder().encode(password);
    const key = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const symmetricKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: hash
        },
        key,
        { name: "AES-GCM", length: keyLength },
        true,
        ["encrypt", "decrypt"]
    );

    return symmetricKey;
}

async function encryptTextWithSymmetricKey(plainText, symmetricKey) {
    // iv is initialization vector, it is used to randomize the encryption
    // so that the same text encrypted with the same key will not have the same output
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedText = new TextEncoder().encode(plainText);
    const encryptedText = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        symmetricKey,
        encodedText
    );

    return {
        encryptedText: arrayBufferToBase64(encryptedText),
        iv: arrayBufferToBase64(iv)
    };

}

async function decryptTextWithSymmetricKey(encryptedTextBase64, ivBase64, symmetricKey) {
   
    const encryptedText = base64ToArrayBuffer(encryptedTextBase64);
    const iv = base64ToArrayBuffer(ivBase64);
    const decryptedText = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        symmetricKey,
        encryptedText
    );

  
    // decode, and return as Base64
    return arrayBufferToBase64(decryptedText);
}

async function encryptPrivateKeyWithSymmetricKey(privateKeyBase64, symmetricKey) {
    // Convert the private key from Base64 to an ArrayBuffer
    const privateKeyArrayBuffer = base64ToArrayBuffer(privateKeyBase64);
            
    // Generate an IV for AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt the private key with the symmetric key
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        symmetricKey, // Directly use the AES-GCM symmetric key
        privateKeyArrayBuffer // Data to encrypt
    );
    
    // Return both the encrypted data and the IV, both as Base64
    return {
        encryptedPrivateKey: arrayBufferToBase64(encryptedData),
        iv: arrayBufferToBase64(iv)
    };
}


// ---------------------------- Asymmetric encryption -----------------------
/**
 * @brief Encrypts a text using the public key in base64 format
 * @param {string} plainText text to be encrypted
 * @param {base64Text} publicKey public key to encrypt the text
 * @returns encrypted text in base64 format
 */
async function encryptText(plainText, publicKey) {
    // We get the public key as a base64 
    const publicKeyArrayBuffer = base64ToArrayBuffer(publicKey);

    // Import the key to crypto subtle
    const importedPublicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyArrayBuffer,
        {
            name: "RSA-OAEP",
            hash: {name: "SHA-256"}
        },
        true,
        ["encrypt"]
    );

    // Do we need to convert the text to array buffer too? 
    const encoder = new TextEncoder();
    const encodedText = encoder.encode(plainText);

    // Encrypt the plain text
    const encryptedText = await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        importedPublicKey,
        encodedText
    );
    
    let encryptedTextBase64 = arrayBufferToBase64(encryptedText);
    return encryptedTextBase64
}

/**
 * @brief Decrypts a text encrypted with asymmetric encryption using the private key in base64 format
 * @param {string} encryptedTextBase64 encrypted text in base64 format
 * @param {base64Text} privateKey private key to decrypt the text
 * @returns decrypted text in string format
 */
async function decryptText(encryptedTextBase64, privateKey) {
    // Convert the private key from Base64 to an array buffer
    const privateKeyArrayBuffer = base64ToArrayBuffer(privateKey);

    // Import the private key into the Web Crypto API
    const importedPrivateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyArrayBuffer,
        {
            name: "RSA-OAEP",
            hash: {name: "SHA-256"}
        },
        true,
        ["decrypt"]
    );

    // Convert the Base64 encrypted text to an array buffer
    const encryptedTextArrayBuffer = base64ToArrayBuffer(encryptedTextBase64);

    // Decrypt the text
    const decryptedTextArrayBuffer = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        importedPrivateKey,
        encryptedTextArrayBuffer
    );

    // We want to return the decrypted text as a string
    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decryptedTextArrayBuffer);

    return decryptedText;
}

// ---------------------------- Helper functions ----------------------------
// Function to convert an array buffer to a base64 function
// arrayBuffer is returned by the Web Crypto API
function arrayBufferToBase64(buffer) {
    // this is needed to convert the array buffer to a string
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));
}

// Function to convert a base64 string to an array buffer
// This is needed to convert the public and private keys 
// to the correct format for the Web Crypto API
function base64ToArrayBuffer(base64Text) {
    const binaryString = window.atob(base64Text);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}


// hash function, password to hash string in base64
async function hashPasswordToBase64(password) {
    // Encode the password as UTF-8
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    // Hash the data
    const hash = await crypto.subtle.digest('SHA-256', data);

    // Convert the hash to a Base64 string
    const hashArray = Array.from(new Uint8Array(hash)); // Convert buffer to byte array
    const base64String = btoa(String.fromCharCode.apply(null, hashArray));

    return base64String;
}