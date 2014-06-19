package edu.berkeley.cas.authentication.principal;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;

/**
 * Class to resolve surrogate principals
 */
class SurrogateUsernamePasswordCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver {
    @Override
    protected String extractPrincipalId(Credentials credentials) {
        return ((SurrogateUsernamePasswordCredentials)credentials).getTargetUsername();
    }

    @Override
    public boolean supports(Credentials credentials) {
        return credentials != null && SurrogateUsernamePasswordCredentials.class.isAssignableFrom(credentials.getClass());
    }
}
