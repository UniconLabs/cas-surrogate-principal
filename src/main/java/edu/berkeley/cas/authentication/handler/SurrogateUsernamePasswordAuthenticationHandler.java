package edu.berkeley.cas.authentication.handler;

import edu.berkeley.cas.authentication.principal.SurrogateUsernamePasswordCredentials;
import edu.berkeley.cas.authentication.service.SurrogateUsernamePasswordService;
import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.AuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

import org.jasig.cas.authentication.handler.BadUsernameOrPasswordAuthenticationException;

/**
 * Class to handle surrogate authentication
 */
class SurrogateUsernamePasswordAuthenticationHandler implements AuthenticationHandler {
    private java.util.List<org.jasig.cas.authentication.handler.AuthenticationHandler> authenticationHandlerList;
    private SurrogateUsernamePasswordService surrogateUsernamePasswordService;

    @Override
    public boolean authenticate(Credentials credentials) throws AuthenticationException {
        SurrogateUsernamePasswordCredentials surrogateUsernamePasswordCredentials = (SurrogateUsernamePasswordCredentials) credentials;

        UsernamePasswordCredentials usernamePasswordCredentials = new UsernamePasswordCredentials();
        usernamePasswordCredentials.setUsername(surrogateUsernamePasswordCredentials.getUsername());
        usernamePasswordCredentials.setPassword(surrogateUsernamePasswordCredentials.getPassword());

        for (AuthenticationHandler handler: this.authenticationHandlerList) {
            if (handler.supports(usernamePasswordCredentials)
                    && handler.authenticate(usernamePasswordCredentials)
                    && this.surrogateUsernamePasswordService.canAuthenticateAs(surrogateUsernamePasswordCredentials.getTargetUsername(), surrogateUsernamePasswordCredentials.getUsername())) {
                return true;
            }
        }
        throw new BadSurrogateAuthenticationException();
    }

    @Override
    public boolean supports(Credentials credentials) {
        return credentials != null && SurrogateUsernamePasswordCredentials.class.isAssignableFrom(credentials.getClass());
    }

    public void setAuthenticationHandlerList(java.util.List<AuthenticationHandler> authenticationHandlerList) {
        this.authenticationHandlerList = authenticationHandlerList;
    }

    public void setSurrogateUsernamePasswordService(SurrogateUsernamePasswordService surrogateUsernamePasswordService) {
        this.surrogateUsernamePasswordService = surrogateUsernamePasswordService;
    }
}
