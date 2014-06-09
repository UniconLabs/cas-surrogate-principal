package edu.berkeley.cas.authentication.principal;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

/**
 * Class to resolve surrogate principals
 */
public class SurrogateUsernamePasswordCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver {
    /**
     * The String that separates the parts of the username, eg "+" in "group+username"
     */
    String separator = "+";

    @Override
    protected String extractPrincipalId(Credentials credentials) {
        String passedUsername = ((UsernamePasswordCredentials) credentials).getUsername();
        return passedUsername.substring(0, passedUsername.indexOf(this.separator));
    }

    @Override
    public boolean supports(Credentials credentials) {
        return credentials != null
                && UsernamePasswordCredentials.class.isAssignableFrom(credentials.getClass())
                && ((UsernamePasswordCredentials) credentials).getUsername().contains(separator);
    }

    public void setSeparator(String separator) {
        this.separator = separator;
    }
}
