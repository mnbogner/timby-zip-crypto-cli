package org.timby.zipcrypto.services;

/**
 * FileCryptoService
 */
public interface FileCryptoService {

    public byte[] encrypt(int userId, String encodedUserPubKey, String encodedServerPubKey, String hashedPassword, byte[] blob);

    public byte[] decrypt(String encodedUserPubKey, String encodedUserPrivateKey, String encodedServerPubKey, String encodedServerPrivateKey, byte[] blob);
}
