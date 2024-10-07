package javax.net.ssl;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * This class handels the GCM encryption and decryption.
 */
public class GCM {

    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String FACTORY_INSTANCE = "PBKDF2WithHmacSHA512";
    private static final int TAG_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 32;
    private static final int ITERATIONS = 65535;

    /**
     * Empty Constructor
     *
     * */
    public GCM() {

    }

    /**
     * Return secret
     *
     * @param password as char array
     * @param salt as byte array
     * @return secret of Type SecretKey
     * */
    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH * 8);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    /**
     * Return decrypted text
     *
     * @param cipherContent as string
     * @param password as string
     * @return decrypted text
     * @throws Exception incase something happens
     * */
    public static byte[] decrypt(byte[] cipherContent, String password) throws Exception {
        byte[] decode = cipherContent; //Base64.getDecoder().decode(cipherContent);
        ByteBuffer byteBuffer = ByteBuffer.wrap(decode);

        byte[] salt = new byte[SALT_LENGTH];
        byteBuffer.get(salt);

        byte[] iv = new byte[IV_LENGTH];
        byteBuffer.get(iv);

        byte[] content = new byte[byteBuffer.remaining()];
        byteBuffer.get(content);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH * 8, iv));
        byte[] plainText = cipher.doFinal(content);
        return plainText;
    }

    /**
     * Return encrypted text
     *
     * @param password as string
     * @param plainMessage as byte array
     * @return encrypted text
     * @throws Exception incase something happens
     * */
    public static byte[] encrypt(String password, byte[] plainMessage) throws Exception {
        byte[] salt = getRandomNonce(SALT_LENGTH);
        SecretKey secretKey = getSecretKey(password, salt);

        byte[] iv = getRandomNonce(IV_LENGTH);

        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedMessageByte = cipher.doFinal(plainMessage);

        byte[] cipherByte = ByteBuffer.allocate(salt.length + iv.length + encryptedMessageByte.length)
                .put(salt)
                .put(iv)
                .put(encryptedMessageByte)
                .array();
        return cipherByte;
    }

    /**
     * Return nonce
     *
     * @param length as int
     * @return nonce
     * */
    public static byte[] getRandomNonce(int length) {
        byte[] nonce = new byte[length];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Return secret
     *
     * @param password as String
     * @param salt as byte array
     * @return secret of Type SecretKey
     * @throws NoSuchAlgorithmException incase something happens
     * @throws InvalidKeySpecException incase something happens
     * */
    public static SecretKey getSecretKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH * 8);

        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_INSTANCE);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /**
     * Return cipher
     *
     * @param mode as int
     * @param secretKey as SecretKey
     * @param iv as byte array
     * @return cipher of Type Cipher
     * @throws InvalidKeyException incase something happens
     * @throws InvalidAlgorithmParameterException incase something happens
     * @throws NoSuchPaddingException incase something happens
     * @throws NoSuchAlgorithmException incase something happens
     * */
    private static Cipher initCipher(int mode, SecretKey secretKey, byte[] iv) throws InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(mode, secretKey, new GCMParameterSpec(TAG_LENGTH * 8, iv));
        return cipher;
    }

}