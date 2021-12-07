package io.ttrms.crypt;

public class TittyCryptoException extends Exception {

    /**
     * Mostly used as a wrapper for the large number of Exceptions thrown by crypto libraries
     *
     * @param ex The exception that caused crypto operations to fail
     */
    public TittyCryptoException(Exception ex) {
        super(String.format("Crypto lib failed big-time: %s", ex.getClass()), ex);
    }
}
