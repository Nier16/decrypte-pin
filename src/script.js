// // var passPhrase = "The Moon is a Harsh Mistress.";
// // var bits = 1024;
// // var message = "TEST ME !!";
// //
// // var rsaKey = cryptico.generateRSAKey(passPhrase, bits);
// // var publicKeyString = cryptico.publicKeyString(rsaKey);
// //
// // console.log("publicKey : ", publicKeyString);
// //
// // var encrypted = cryptico.encrypt(message, publicKeyString);
// // console.log("encrypted message : ", encrypted);
// // var decrypted = cryptico.decrypt(encrypted.cipher, rsaKey);
// //
// //
// // console.log("decrypted message : ", decrypted);
//
//
// // Generate RSA key pair
// // var text = 'rpIbhs67wEklyMANzB/I5Q==';
// // var key = '61A402A2AD37BC383B1640BF40CB34E6';
// //
// // console.log('text:', btoa(text));
// // console.log('key:', key);
// // console.log('key length:', key.length );
// //
// //
// //
// // // Fix: Use the Utf8 encoder (or apply in combination with the hex encoder a 32 hex digit key for AES-128)
// // key = CryptoJS.enc.Hex.parse(key);
// //
// // // Fix: Pass a CipherParams object (or the Base64 encoded ciphertext)
// // var decrypted =  CryptoJS.AES.decrypt({ciphertext: CryptoJS.enc.Hex.parse(text)}, key, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.ZeroPadding });
// // // Fix: Utf8 decode the decrypted data
// // console.log('decrypted', decrypted.toString(CryptoJS.enc.Hex));
//
// function decryptAES(encryptedPinBlock, key) {
//     const decrypted = CryptoJS.AES.decrypt(
//         { ciphertext: encryptedPinBlock },
//         CryptoJS.enc.Hex.parse(key),
//         { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.ZeroPadding}
//     );
//     return decrypted.toString(CryptoJS.enc.Hex);
// }
//
// function xorStrings(str1, str2) {
//     const binaryStr1 = BigInt(`0b${str1}`);
//     const binaryStr2 = BigInt(`0b${str2}`);
//
//     const result = (binaryStr1 ^ binaryStr2).toString(2);
//
//     return result.padStart(str1.length, '0');
// }
//
// function xorHexStrings(hexString1, hexString2) {
//     const binaryString1 = hexToBinary(hexString1);
//     const binaryString2 = hexToBinary(hexString2);
//
//     const xorResult = xorStrings(binaryString1, binaryString2);
//
//     return binaryToHex(xorResult);
// }
//
// function hexToBinary(hexString) {
//     return BigInt(`0x${hexString}`).toString(2);
// }
//
// function binaryToHex(binaryString) {
//     return BigInt(`0b${binaryString}`).toString(16);
// }
//
// // Exemple d'utilisation
// const panBlock = '5135398029906653';
// const ktaEncrypted = 'rpIbhs67wEklyMANzB/I5Q==';
// const pinBlockEncrypted = 'kScALc6D0lf7szL0JtXnsw==';
// const ktkDecrypted = '61A402A2AD37BC383B1640BF40CB34E6';
//
//
//
// const ktaDecrypted = decryptAES(CryptoJS.enc.Base64.parse(ktaEncrypted), ktkDecrypted);
// console.log('ktaDecrypted:', ktaDecrypted);
//
// const pinBlockDecrypted = decryptAES(CryptoJS.enc.Base64.parse(pinBlockEncrypted), ktaDecrypted);
// console.log('pinBlockDecrypted:', pinBlockDecrypted);
//
// const formattedPan = ('4' + panBlock).padEnd(32, '0');
// console.log("formattedPan : ", formattedPan);
//
// const intermediateXorBlock = xorHexStrings(formattedPan, pinBlockDecrypted);
// console.log("intermediateXorBlock : ", intermediateXorBlock);
//
// const cleanPinBlock = decryptAES(CryptoJS.enc.Hex.parse(intermediateXorBlock), ktaDecrypted);
// console.log("cleanPin : ", cleanPinBlock);
//
// const pinSize = parseInt(cleanPinBlock.charAt(1));
// const pin = cleanPinBlock.substring(2, pinSize + 2);
// console.log("pinSize : ", pinSize);
// console.log("pin : ", pin);
//

// ----------------------------------- MOCK PART ------------------------------ //

const panBlockEncrypted = 'C01Ecp7hKr3xwXvOME55QWl_A';
const panBlockDecrypted = '5135398029906653';
const salt = "000051353980299066539999";


function mockGenerateRSAKeyPair(){
    const privateKeyText = '-----BEGIN RSA PRIVATE KEY-----' +
        'MIIEowIBAAKCAQEAgTGVywqSSx2LR8NtVGQC/W9IgmMTvva+pYPZjq1gVhjgP7J+' +
        '4wgXPI4X1oHjZhDSUTJAY9uLszrfco5DGscCW68GYE0Fck8aNIMlWPqPJXvHoa5x' +
        '6N56ioeaA9X2HmaAUQXYWUUzN8yIBMd7kSKOqq8reS3I0Z7BYmFV7k1OVTTNoEes' +
        'dddP3jJjwWncZm7YHra7soUxuylMb1Y+5B6bEeKXFoXqEdbR3OvGgIJWpScsKpDr' +
        'ajll6J/Ylm0JQl0q4lmIA0VUng5GA6QFEr/63iQ4EN8FiD4TF7AzKb+uL10wY63b' +
        'dUj/kMJnDOwWnk2NysR8/YYsdrdP18+b+xM9JQIDAQABAoIBAEiVZycP5Wk2TA4h' +
        'iccj+VoRr5cxuuJLFok/LneuiLVWfIbM7eT3orZuzo3Bo9SwFrlvliWEL1Se+vMN' +
        'Yj4lGPoRt29bVngGYR6nn9AB1XKlvF7l9zFx7T7vOGR3TTN/OxBKTGa7Li9nRfQJ' +
        'by73T1gt2irWwkCjBNsU/IZKAHx1xJ+Oh9XdiNHe/cDuSHjhexOkBgaFi6SnMbJK' +
        '0rUSTcCL4Si90+waI6t5cw/Uqj1Yr7KEay1aeqYe/zCLQ8uEc/7fzGF4htlqLZhA' +
        'XLEsOEh4p5eX4psFPiKOVA4/Izyl5B+5BY2S8pgVaMuhC8n/pNatolm3ekq+7/CX' +
        'qrlFXoECgYEAykK5ymLrhCSuV6eMpP2YkGXnoZfH+RAovZATwB8SOXGAjI/0DPvu' +
        'rt3tPfVOZRnjKOd2Uc1egYYXArgrBnsO1ptidKxbsOtplzCfgtFlbRJ/6iRWw0Ax' +
        'NU1jhAL8o8TguAHM/qWGo5MZcLxEpB5w0/lgWIqYjPW+6U8fsWjbbS0CgYEAo4UG' +
        'HTmf2mm6OcRml8fFJh5TRqPSiY4H/r7M/KSV/4uRq2FIRWs+jAbigpVT96X/3lzM' +
        '6Yd09wOarlL9wqenxc5n8AnetR8usBYyAEGR4znZpTiLFJFcbO9I8HmzJnqNmK/9' +
        'zg2/E5PsM/b6jO0w6vGbXilFpQzvNEhkFJ1lutkCgYBqKZHZUAisiJBWA+THqTBO' +
        'Ap8M610UNs4biadEPUrUieXeYaTIt+e1M1lWHw7x9B+Olcc98py7QYWMcNxsf2Tv' +
        'cgnAkcNi3n3C1Mu033HsSTyIymAcBfKONruYS/UNhMYq7w8JThqYexpsWPVya2Pv' +
        'b0KJ1t1xh3+YeGZ7OT2LVQKBgDuQnG6O7CUCuHyMh5aoha9iApHL4UiMPWtVk5RA' +
        'XAePjsuwD0SCUXFunJpWzRR8Gp2kjlxPJJNKc9EmmBuNOPc8Pe5Zmg++QSKRozsm' +
        'p37vNtIRq9AdN17TN22p11Gf+O5yxXCG32DBVJyFTjWBvX0H78G4JQ9/i68u444C' +
        '2+jZAoGBAMbMKA/gAI56PrpTjUbUih2kzdfGJ2PIjXeBElUlBqc3UxqGWkgYfuq8' +
        'vC6LZQPc+OnvnSFO+HPD43nSmXqi3c60dHhKhcBubNhL4CTTYFJpk8gvhEvUUXTa' +
        '2cNVaK8WL2fwjScJeMn17qW8rIrcjuVrkFpXZTkVfIODmEnubfDL' +
        '-----END RSA PRIVATE KEY-----';

    const publicKey = '-----BEGIN PUBLIC KEY-----' +
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgTGVywqSSx2LR8NtVGQC' +
        '/W9IgmMTvva+pYPZjq1gVhjgP7J+4wgXPI4X1oHjZhDSUTJAY9uLszrfco5DGscC' +
        'W68GYE0Fck8aNIMlWPqPJXvHoa5x6N56ioeaA9X2HmaAUQXYWUUzN8yIBMd7kSKO' +
        'qq8reS3I0Z7BYmFV7k1OVTTNoEesdddP3jJjwWncZm7YHra7soUxuylMb1Y+5B6b' +
        'EeKXFoXqEdbR3OvGgIJWpScsKpDrajll6J/Ylm0JQl0q4lmIA0VUng5GA6QFEr/6' +
        '3iQ4EN8FiD4TF7AzKb+uL10wY63bdUj/kMJnDOwWnk2NysR8/YYsdrdP18+b+xM9' +
        'JQIDAQAB' +
        '-----END PUBLIC KEY-----';
    return {privateKey : forge.pki.privateKeyFromPem(privateKeyText), publicKey : forge.pki.publicKeyFromPem(publicKey)};
}

function mockPinServiceCall(){
    return new Promise(resolve => {
        setTimeout(() => resolve({
            pinBlock: 'kScALc6D0lf7szL0JtXnsw==',
            kta: 'rpIbhs67wEklyMANzB/I5Q==',
            ktk: 'QoXDarHZjP5+kZPB44zchmqX6VuKE/2lcH8Eya1Uux/vqNiz/AGqgKxV57j2Sr6BRPkZ/whx2FC4HRe0vqXqCw43cfX4ZX9pmkwO1MhDfGNjriyK7IV/0za+HaZpzj9NDum3G3hW404Wq6HGJwdgdjy4roljnzG8wtobLu/GAdrrHOQO1RB3xMs91645tcUdT6jwulnmKdEYc3rdW05c/cJB3u8TZrpO0Wbk084UNaJDRz4//KdCLZaZFHlQIxim80tLuB1l6hz5Fb9X2Q4RwYh3OC7zwQ4X7kq0N8mCUxT4ePCrj529fkfZrit3jnzhtwCYC11P7q3dbEWxFiebdw=='
        }), 1000);
    });
}

//------------------------------------------------------------------------------//



function generateRSAKeyPair() {
    return forge.pki.rsa.generateKeyPair({bits: 2048});
}


// Decrypt data with RSA using PKCS#1 padding
function decryptWithRSA(encryptedData, privateKey) {
    const encrypted = forge.util.decode64(encryptedData);
    const decryptedBytes = privateKey.decrypt(encrypted, 'RSAES-PKCS1-V1_5');
    return forge.util.bytesToHex(decryptedBytes);
}


function decryptAES(encryptedMessage, key, isInHex) {
    const decipher = forge.cipher.createDecipher('AES-ECB', forge.util.hexToBytes(key));
    decipher.start({ iv: '' });
    if(isInHex){
        decipher.update(forge.util.createBuffer(forge.util.hexToBytes(encryptedMessage)));
    }else{
        decipher.update(forge.util.createBuffer(encryptedMessage, 'base64'));
    }
    decipher.finish();
    return decipher.output.toHex();
}

function xorStrings(str1, str2) {
    const binaryStr1 = BigInt(`0b${str1}`);
    const binaryStr2 = BigInt(`0b${str2}`);

    const result = (binaryStr1 ^ binaryStr2).toString(2);

    return result.padStart(str1.length, '0');
}

function xorHexStrings(hexString1, hexString2) {
    const binaryString1 = hexToBinary(hexString1);
    const binaryString2 = hexToBinary(hexString2);

    const xorResult = xorStrings(binaryString1, binaryString2);

    return binaryToHex(xorResult);
}

function hexToBinary(hexString) {
    return BigInt(`0x${hexString}`).toString(2);
}

function binaryToHex(binaryString) {
    return BigInt(`0b${binaryString}`).toString(16);
}


const rsaKeys = generateRSAKeyPair();
const rsaKeysMock = mockGenerateRSAKeyPair();
const privateKey = rsaKeysMock.privateKey;
mockPinServiceCall().then(r => {
    decryptPin(privateKey, panBlockEncrypted, panBlockEncrypted, salt, r.ktk, r.kta, r.pinBlock);
});

const decryptPin = (privateKey, panEncrypted, panDecrypted, salt, ktk, kta, pinBlock) => {
    const fullKtk = decryptWithRSA(ktk, privateKey);
    if(fullKtk.indexOf(salt) !== 0){
        console.error("Le ktk ", fullKtk, " ne commence pas par le salt ", salt);
        return;
    }

    const ktaDecrypted = decryptAES(forge.util.decode64(kta), fullKtk.substring(salt.length));

    const pinBlockDecrypted = decryptAES(forge.util.decode64(pinBlock), ktaDecrypted);

    const formattedPan = ('4' + panBlockDecrypted).padEnd(32, '0');

    const intermediateXorBlock = xorHexStrings(formattedPan, pinBlockDecrypted);

    const cleanPinBlock = decryptAES(intermediateXorBlock, ktaDecrypted, true);

    const pinSize = parseInt(cleanPinBlock.charAt(1));

    const pin = cleanPinBlock.substring(2, pinSize + 2);


    console.log("fullKtk: ", fullKtk);
    console.log("pureKtk: ", fullKtk.substring(salt.length));
    console.log('ktaDecrypted:', ktaDecrypted);
    console.log('pinBlockDecrypted:', pinBlockDecrypted);
    console.log("formattedPan: ", formattedPan);
    console.log("intermediateXorBlock: ", intermediateXorBlock);
    console.log("cleanPin: ", cleanPinBlock);
    console.log("pinSize: ", pinSize);
    console.log("pin: ", pin);

    return pin;
}

// Example usage


// const pinBlockEncrypted = 'kScALc6D0lf7szL0JtXnsw==';
// const ktkDecrypted = '61A402A2AD37BC383B1640BF40CB34E6';



















console.log(generateRSAKeyPair());





