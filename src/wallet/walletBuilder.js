import nacl from '../external/nacl-fast';
import helpers from '../crypto/cryptoHelpers'
import keyPair from '../crypto/keyPair';
import address from '../model/address';
import cryptoHelpersFromNano from '../nano/CryptoHelpers';

let createWallet = function (walletName, walletPassword, network, crypto) {
    return new Promise((resolve, reject) => {

        // Create random bytes
        let r = dim.utils.convert.ua2hex(crypto ? crypto.secureRandomBytes(32) : nacl.randomBytes(32));

        // Derive private key from random bytes + entropy seed
        let privateKey = helpers.derivePassSha(r, 1000).priv;
        // Create KeyPair
        let k = keyPair.create(privateKey);
        // Create address from public key
        let addr = address.toAddress(k.publicKey.toString(), network);
        // Encrypt private key using password
        let encrypted = helpers.encodePrivKey(privateKey, walletPassword);
        // Create bip32 remote amount using generated private key
        return resolve(cryptoHelpersFromNano.generateBIP32Data(privateKey, walletPassword, 0, network).then((data) => {
            // Construct the wallet object
            let wallet = buildWallet(walletName, addr, true, "pass:bip32", encrypted, network, data.publicKey);
            return wallet;
        },
            (err) => {
                return err;
            }));
    });
}

let buildWallet = function (walletName, addr, brain, algo, encrypted, network, child) {
    let wallet = {
        "name": walletName,
        "accounts": {
            "0": {
                "brain": brain,
                "algo": algo,
                "encrypted": encrypted.ciphertext || "",
                "iv": encrypted.iv || "",
                "address": addr.toUpperCase().replace(/-/g, ''),
                "label": 'Primary',
                "network": network,
                "child": child
            }
        }
    };
    return wallet;
}

module.exports = {
    createWallet
}
