package edu.berkeley.cas.authentication.handler;

import org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException;
import org.jasig.cas.authentication.handler.BadUsernameOrPasswordAuthenticationException;

/**
 * Exception thrown when a bad surrogate authentication occurs.
 */
public class BadSurrogateAuthenticationException extends BadCredentialsAuthenticationException {
    private static final String CODE = "error.authentication.credentials.bad.surrogate";
    public BadSurrogateAuthenticationException() {
        super(CODE);
    }

    /**
     * @see org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException#BadCredentialsAuthenticationException(java.lang.Throwable)
     */
    public BadSurrogateAuthenticationException(Throwable throwable) {
        super(CODE, throwable);
    }

    /**
     * @see org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException#BadCredentialsAuthenticationException(java.lang.String)
     */
    public BadSurrogateAuthenticationException(String code) {
        super(code);
    }

    /**
     * @see org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException#BadCredentialsAuthenticationException(java.lang.String, java.lang.Throwable)
     */
    public BadSurrogateAuthenticationException(String code, Throwable throwable) {
        super(code, throwable);
    }
}
