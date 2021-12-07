package io.ttrms.crypt;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class CryptSpec {

    /**
     * Encryption algorithm to use.
     *
     * @see <a href="https://stackoverflow.com/a/56428353/9665770">How can I list the available Cipher algorithms? (StackOverflow)</a>
     */
    private final String encryptAlgo;

    // Todo: Find available options
    private final String secretKeyAlgo;

    /**
     * Recommended being set to <code>16</code>
     */
    private final int saltByteLength;

    /**
     * Recommended being set to <code>12</code>
     */
    private final int ivByteLength;

    /**
     * Recommended being set to <code>128</code>
     */
    private final int tagBitLength;

    /**
     * At least <code>100,000</code> is recommended.
     * Increase at <code>10,000</code> intervals.
     * Can exponentially increase amount of time encryption/decryption takes.
     * Use low values if targeting low-powered CPU's.
     */
    private final int iterationCount;

    /**
     * Recommended being set to <code>256</code>
     */
    private final int keyLength;
}
