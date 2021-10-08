package io.ttrms;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Crypt {
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final String SECRET_KEY_ALGO = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH_BYTE = 16;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int TAG_LENGTH_BIT = 128; // Must be one of {128, 120, 112, 104, 96}
    private static final int ITERATION_COUNT = 250_420;
    private static final int KEY_LENGTH = 256;
    private final String password;

    public Crypt(String password) {
        this.password = password;
    }

    public static void main(String[] args) throws TittyCryptoException {
        String sensitiveInformation = "nuclear-launch-codes";
        String password = "HighlySecure123!";

        Crypt crypt = new Crypt(password);

        String encrypted = crypt.encrypt(sensitiveInformation);
        System.out.println(encrypted);

        String decrypted = crypt.decrypt(encrypted);
        System.out.println(decrypted);
    }

    /**
     * Returns an MD5 hash of the provided String
     *
     * @see <a href="https://www.geeksforgeeks.org/md5-hash-in-java/">MD5 Hash in Java (Geeks for Geeks)</a>
     */
    @SuppressWarnings("unused")
    public static String getMd5(String input) throws NoSuchAlgorithmException {
        String hashText = new BigInteger(1, MessageDigest.getInstance("MD5").digest(input.getBytes())).toString(16);
        while (hashText.length() < 32) hashText = "0".concat(hashText);
        return hashText;
    }

    /**
     * Cryptographically generate random data for salting
     */
    private static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Returns a secret key from the provided password
     */
    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(SecretKeyFactory
                .getInstance(SECRET_KEY_ALGO)
                .generateSecret(new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH))
                .getEncoded(), "AES");
    }

    /**
     * Return a base64 encoded AES encrypted text
     *
     * @param data The data to encrypt
     * @return Base64 encoded AES encrypted text
     * @throws TittyCryptoException Thrown if any crypto operations fail
     */
    public String encrypt(String data) throws TittyCryptoException {
        try {

            // 16 bytes random salt
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);

            // GCM recommended 12 bytes iv
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);

            // Secret key derived from password and salt
            SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

            // ASE-GCM needs GCMParameterSpec
            cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] cipherText = cipher.doFinal(data.getBytes(UTF_8));

            // Prefix IV and salt to cipher text for future decrypting
            byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                    .put(iv)
                    .put(salt)
                    .put(cipherText)
                    .array();

            // String representation encoded to Base64
            return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new TittyCryptoException(ex);
        }
    }

    /**
     * Return decoded & decrypted text. IV and salt is derived from the Base64 string
     *
     * @param cText The encoded encrypted data
     * @return The decoded & decrypted text
     * @throws TittyCryptoException Thrown if any crypto operations fail
     */
    public String decrypt(String cText) throws TittyCryptoException {
        try {

            byte[] decode = Base64.getDecoder().decode(cText.getBytes(UTF_8));

            // Get back the IV and salt from the cipher text
            ByteBuffer bb = ByteBuffer.wrap(decode);

            byte[] iv = new byte[IV_LENGTH_BYTE];
            bb.get(iv);

            byte[] salt = new byte[SALT_LENGTH_BYTE];
            bb.get(salt);

            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);

            // Get back the AES key from the same password and salt
            SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

            cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] plainText = cipher.doFinal(cipherText);

            return new String(plainText, UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new TittyCryptoException(ex);
        }
    }
}
