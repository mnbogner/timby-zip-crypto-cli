package org.timby.zipcrypto.services;

class GenericFileCryptoService implements FileCryptoService {

    @Override
    public byte[] encrypt(int userId, String encodedUserPubKey, String encodedServerPubKey, String hashedPassword,
            byte[] blob) {

        return null;
    }

    @Override
    public byte[] decrypt(String encodedUserPubKey, String encodedUserPrivateKey, String encodedServerPubKey,
            String encodedServerPrivateKey, byte[] blob) {
        return null;
    }

}
