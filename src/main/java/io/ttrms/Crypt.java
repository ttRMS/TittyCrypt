package io.ttrms;

import lombok.RequiredArgsConstructor;

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

@RequiredArgsConstructor
public class Crypt {
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private final CryptSpec cryptSpec;
    private final String password;

    /**
     * Purely for testing & sample usage
     */
    public static void main(String[] args) {
        try {
            SampleCrypt.sampleCryptTest();
        } catch (TittyCryptoException ex) {
            ex.printStackTrace();
        }
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
    private byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Returns a secret key from the provided password
     */
    private SecretKey getAESKeyFromPassword(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(SecretKeyFactory
                .getInstance(cryptSpec.getSecretKeyAlgo())
                .generateSecret(new PBEKeySpec(password, salt, cryptSpec.getIterationCount(), cryptSpec.getKeyLength()))
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
            byte[] salt = getRandomNonce(cryptSpec.getSaltByteLength());

            // GCM recommended 12 bytes iv
            byte[] iv = getRandomNonce(cryptSpec.getIvByteLength());

            // Secret key derived from password and salt
            SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance(cryptSpec.getEncryptAlgo());

            // ASE-GCM needs GCMParameterSpec
            cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(cryptSpec.getTagBitLength(), iv));

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

            byte[] iv = new byte[cryptSpec.getIvByteLength()];
            bb.get(iv);

            byte[] salt = new byte[cryptSpec.getSaltByteLength()];
            bb.get(salt);

            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);

            // Get back the AES key from the same password and salt
            SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

            Cipher cipher = Cipher.getInstance(cryptSpec.getEncryptAlgo());

            cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(cryptSpec.getTagBitLength(), iv));

            byte[] plainText = cipher.doFinal(cipherText);

            return new String(plainText, UTF_8);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new TittyCryptoException(ex);
        }
    }
}
