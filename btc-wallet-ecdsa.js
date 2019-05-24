/**
 * Prueba de las librería secp256k1 sobre node
 */
const {randomBytes} = require('crypto');
const secp256k1 = require('secp256k1');
const sha256 = require('js-sha256');
const ripemd160 = require('ripemd160');
const base58 = require('bs58');


const keyGeneration = function(){
    let generatedKey = {};

    // Private key generation
    let privKey;
    do{
        privKey = randomBytes(32);
    } while(!secp256k1.privateKeyVerify(privKey));
    generatedKey.privateKey = privKey;

    // Get public key from private
    const pubKey = secp256k1.publicKeyCreate(privKey);
    generatedKey.publicKey = pubKey;

    return generatedKey;
}


// Generate Wallet Import Format
const generateWIF = function(privateKey){
    let generated = Buffer.from("80" + privateKey.toString('hex'), 'hex');
    let generatedHash = sha256(generated);
    let hashFromHash = sha256(Buffer.from(generatedHash, 'hex'));
    let checksum = hashFromHash.substring(0, 8);
    let wif = generated.toString('hex') + checksum;
    let wifBase58 = base58.encode(Buffer.from(wif, 'hex'));
    return wifBase58;
}


const printKeys = function(generatedKey){
    console.log(`>>>>>>> Generated keys >>>>>>>`);
    console.log(`>>> pk = `, generatedKey.publicKey.toString('hex'));
    console.log(`>>> sk = `, generatedKey.privateKey.toString('hex'));
    console.log(`>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>`)
}


const generatePublicAddress = function(publicKey){
    let ripemd = new ripemd160();
    
    let hash = sha256(publicKey);
    let pkKeyHash = ripemd
        .update(Buffer.from(hash, 'hex'))
        .digest();

    console.log("** Publick key hash = ", pkKeyHash);

    let publicAddress = createAddressFromHash(pkKeyHash);
    return publicAddress;
}


const createAddressFromHash = function(pkKeyHash) {
    // add prefix 00 in hex
    let generated = Buffer.from("00" + pkKeyHash.toString('hex') , 'hex');
    let shaFromGenerated = sha256(generated);
    let shaAgainFromPrevious = sha256(Buffer.from(shaFromGenerated, 'hex'));
    // First byte is the checksum
    let checksum = shaAgainFromPrevious.substring(0, 8);
    // Add checksum to generated
    let generatedWithChecksum = generated.toString('hex') + checksum;
    // Return the address in base 58
    let address = base58.encode(Buffer.from(generatedWithChecksum, 'hex'));
    return address;
}


/*** MAIN EXEC */
const generatedKey = keyGeneration();
printKeys(generatedKey);

// Print address
let publicAddress = generatePublicAddress(generatedKey.publicKey);
console.log(">>>>>> Public Address: ", publicAddress.toString('hex'));

// WIF
let wif = generateWIF(generatedKey.privateKey);
console.log(">>>>>> WIF Address: ", wif.toString('hex'));


// Create msg and sign
const msgToSign = randomBytes(32);
const signedMsg = secp256k1.sign(msgToSign, generatedKey.privateKey);
console.log("Signed message: ", signedMsg);

// Verify signature of message
const isMsgSignedOk = secp256k1.verify(
    msgToSign,
    signedMsg.signature,
    generatedKey.publicKey
);
console.log("Is msg signed ok?", isMsgSignedOk);
