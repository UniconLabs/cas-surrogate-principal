package edu.berkeley.cas.authentication.principal;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;

/**
 * Class to resolve surrogate principals
 */
public class SurrogateUsernamePasswordCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver {
    @Override
    protected String extractPrincipalId(Credentials credentials) {
        throw new UnsupportedOperationException("not yet implemented");
    }

    @Override
    public boolean supports(Credentials credentials) {
        throw new UnsupportedOperationException("not yet implemented");
    }
}
