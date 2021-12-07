package io.ttrms.crypt;

import java.security.Provider;
import java.security.Security;
import java.util.Set;
import java.util.TreeSet;

public class SampleCrypt {

    /**
     * Shows sample usage for {@link Crypt}
     */
    public static void sampleCryptTest() throws TittyCryptoException {
        String sensitiveInformation = "nuclear-launch-codes";
        String password = "HighlySecure123!";

        CryptSpec cryptSpec = new CryptSpec(
                "AES_256/GCM/NoPadding",
                "PBKDF2WithHmacSHA256",
                16,
                12,
                128,
                250_420,
                256);


        Crypt crypt = new Crypt(cryptSpec, password);

        String encrypted = crypt.encrypt(sensitiveInformation);
        System.out.println(encrypted);

        String decrypted = crypt.decrypt(encrypted);
        System.out.println(decrypted);

        /*for (String algo : getAvailableEncryptAlgos())
            System.out.println(algo);*/
    }

    /**
     * Return an array of possible argument values for {@link CryptSpec} <code>encryptAlgo</code>
     *
     * @see <a href="https://stackoverflow.com/a/56428353/9665770">How can I list the available Cipher algorithms? (StackOverflow)</a>
     */
    @SuppressWarnings("unused")
    public static String[] getAvailableEncryptAlgos() {
        Set<String> algos = new TreeSet<>();
        for (Provider provider : Security.getProviders())
            provider.getServices().stream()
                    .filter(s -> "Cipher".equals(s.getType()))
                    .map(Provider.Service::getAlgorithm)
                    .forEach(algos::add);
        return algos.toArray(new String[]{});
    }
}
