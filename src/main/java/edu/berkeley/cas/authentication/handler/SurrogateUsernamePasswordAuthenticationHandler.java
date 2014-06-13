package edu.berkeley.cas.authentication.handler;

import edu.berkeley.cas.authentication.service.SurrogateUsernamePasswordService;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

import org.jasig.cas.authentication.handler.BadUsernameOrPasswordAuthenticationException;

/**
 * Class to handle surrogate authentication
 */
public class SurrogateUsernamePasswordAuthenticationHandler implements AuthenticationHandler {
    java.util.List<org.jasig.cas.authentication.handler.AuthenticationHandler> authenticationHandlerList;
    SurrogateUsernamePasswordService surrogateUsernamePasswordService;

    /**
     * The String that separates the parts of the username, eg "+" in "group+username"
     */
    String separator = "+";

    @Override
    public boolean authenticate(Credentials credentials) throws AuthenticationException {
        // TODO: this is not safe! we should explore making credentials cloneable!
        UsernamePasswordCredentials usernamePasswordCredentials = (UsernamePasswordCredentials) credentials;
        boolean value = false;
        String passedUsername = usernamePasswordCredentials.getUsername();
        String surrogateUsername = passedUsername.substring(passedUsername.indexOf(separator) + 1);
        String targetUsername = passedUsername.substring(0, passedUsername.indexOf(separator));
        usernamePasswordCredentials.setUsername(surrogateUsername);
        for (AuthenticationHandler handler : this.authenticationHandlerList) {
            if (handler.supports(usernamePasswordCredentials)
                    && handler.authenticate(usernamePasswordCredentials)
                    && this.surrogateUsernamePasswordService.canAuthenticateAs(targetUsername, surrogateUsername)) {

                usernamePasswordCredentials.setUsername(passedUsername);
                return true;
            }
        }
        throw new BadUsernameOrPasswordAuthenticationException("Make sure to use `group+username`");
    }

    @Override
    public boolean supports(Credentials credentials) {
        return credentials != null
                && UsernamePasswordCredentials.class.isAssignableFrom(credentials.getClass())
                && ((UsernamePasswordCredentials) credentials).getUsername().contains(separator);
    }

    public void setAuthenticationHandlerList(java.util.List<AuthenticationHandler> authenticationHandlerList) {
        this.authenticationHandlerList = authenticationHandlerList;
    }

    public void setSurrogateUsernamePasswordService(SurrogateUsernamePasswordService surrogateUsernamePasswordService) {
        this.surrogateUsernamePasswordService = surrogateUsernamePasswordService;
    }

    void setSeparator(String separator) {
        this.separator = separator;
    }
}
