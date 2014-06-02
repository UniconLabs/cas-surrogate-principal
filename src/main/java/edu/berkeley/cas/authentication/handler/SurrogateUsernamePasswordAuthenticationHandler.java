package edu.berkeley.cas.authentication.handler;

import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.handler.AuthenticationException;

/**
 * Class to handle surrogate authentication
 */
public class SurrogateUsernamePasswordAuthenticationHandler implements AuthenticationHandler {
    @Override
    public boolean authenticate(Credentials credentials) throws AuthenticationException {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public boolean supports(Credentials credentials) {
        throw new UnsupportedOperationException("not yet implemented");
    }
}
