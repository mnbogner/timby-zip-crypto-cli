package org.timby.zipcrypto;

import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import com.sun.jna.Platform;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.Banner;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import org.apache.commons.io.FileUtils;
import com.google.common.primitives.Bytes;

import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;

@SpringBootApplication
public class Application implements CommandLineRunner {
    private byte[] serverPubKey;
    private byte[] userPubKey;
    private String passwordHash;
    private int userId;
    private byte[] zipBytes;
    private byte[] serverPrivateKey;
    private byte[] userPrivateKey;
    private final static String HASH_ALGORITHM = "HmacSHA256";
    private static Logger logger = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(Application.class);
        app.setBannerMode(Banner.Mode.OFF);
        app.run(args);
    }

    @Override
    public void run(String... args) throws IOException, SodiumLibraryException, Exception {
        if (args.length < 4) {
            System.exit(-1);
        }

        serverPubKey = Base64.getDecoder().decode(args[0]);
        userPubKey = Base64.getDecoder().decode(args[1]);
        serverPrivateKey = Base64.getDecoder().decode(args[4]);
        userPrivateKey = Base64.getDecoder().decode(args[5]);
        passwordHash = args[6];
        try {
            userId = Integer.parseInt(args[2]);
        } catch (NumberFormatException e) {
            userId = 0;
        }
        logger.info("userId {}", userId);

        File zipFile = new File(args[3]);
        zipBytes = FileUtils.readFileToByteArray(zipFile);
        logger.info("zipFile: {}", zipFile);

        String platform = System.getProperty("os.name");
        String libraryPath = "";
        logger.info("Platform: " + platform);
        if (Platform.isMac()) {
            libraryPath = "/usr/local/lib/libsodium.dylib";
            logger.info("Library path in Mac: " + libraryPath);
        } else if (Platform.isLinux()) {
            libraryPath = "/usr/local/lib/libsodium.so";
            logger.info("Library path in Linux: " + libraryPath);
        } else {
            // TODO: I don't have a Window machine, nor do I care at this moment
            throw new Exception("Window is not supported yet");
        }
        logger.info("Initialize libsodium...");
        SodiumLibrary.setLibraryPath(libraryPath);
        logger.info("Library path: " + libraryPath);
        String v = SodiumLibrary.libsodiumVersionString();
        logger.info("libsodium version: " + v);

        byte[] userCipherBytes = SodiumLibrary.cryptoBoxSeal(zipBytes, userPubKey);

        // Check decryption works
        // byte[] decryptedBytes = SodiumLibrary.cryptoBoxSealOpen(userCipherBytes,
        // userPubKey, userPrivateKey);
        // File outFile = new File(zipFile + ".timby");
        // FileUtils.writeByteArrayToFile(outFile, decryptedBytes);

        byte[] userIdAsBytes = intergerTo8Bytes(userId);
        byte[] concatBytes = Bytes.concat(userIdAsBytes, userCipherBytes);
        byte[] pubCipherBytes = SodiumLibrary.cryptoBoxSeal(concatBytes, serverPubKey);

        byte[] magicNumberBytes = intergerTo8Bytes(154);
        byte[] versionBytes = intergerTo8Bytes(1);
        // user id again
        byte[] hmacBytes = generateHMACSignature(passwordHash, zipBytes); // 32
        byte[] lengthBytes = intergerTo8Bytes(zipBytes.length);

        // full header for final package
        // 8 bytes: magic
        // 8 bytes: version
        // 8 bytes: userId
        // 32 bytes: hmac
        // 8 bytes: length
        byte[] fileBytes = Bytes.concat(magicNumberBytes, versionBytes, userIdAsBytes, hmacBytes, lengthBytes,
                pubCipherBytes);

        File outFile = new File(zipFile + ".timby");
        FileUtils.writeByteArrayToFile(outFile, fileBytes);

        // Try Decryption now
        // File encryptedFile = new File(zipFile + ".timby");
        // byte[] secretData = FileUtils.readFileToByteArray(encryptedFile);
        // byte[] Bytes = SodiumLibrary.cryptoBoxSealOpen(userCipherBytes, serverPubKey,
        // userPrivateKey);

    }

    private byte[] intergerTo8Bytes(int aNumber) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(8);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        byteBuffer.putInt(aNumber);
        return byteBuffer.array();
    }

    private byte[] generateHMACSignature(String passwordHash, byte[] archiveBlob) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(32);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        if (passwordHash.isEmpty()) {
            byteBuffer.putInt(0);
        } else {
            // Create an instance of the hash algorithm and create the URL signature.
            SecretKeySpec secretKey;
            try {
                secretKey = new SecretKeySpec(passwordHash.getBytes("UTF-8"), HASH_ALGORITHM);

                final Mac mac; // Stands for Messages Authentication Code

                try {
                    mac = Mac.getInstance(HASH_ALGORITHM);

                    try {
                        mac.init(secretKey);
                    } catch (final InvalidKeyException ex) {
                        //throw new Exception(ex);
                        ex.printStackTrace();
                    }

                    final byte[] signature = mac.doFinal(archiveBlob);
                    byteBuffer.put(signature);
                } catch (final NoSuchAlgorithmException ex) {
                    // throw new Exception(ex);
                    ex.printStackTrace();
                }

            } catch (UnsupportedEncodingException ex) {

                ex.printStackTrace();
                byteBuffer.putInt(0);
            }
        }

        return byteBuffer.array();
    }
}
