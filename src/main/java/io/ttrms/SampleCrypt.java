package io.ttrms;

public class SampleCrypt {
    public static void sampleCryptTest() throws TittyCryptoException {
        String sensitiveInformation = "nuclear-launch-codes";
        String password = "HighlySecure123!";

        Crypt crypt = new Crypt(password);

        String encrypted = crypt.encrypt(sensitiveInformation);
        System.out.println(encrypted);

        String decrypted = crypt.decrypt(encrypted);
        System.out.println(decrypted);
    }
}
