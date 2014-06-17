package edu.berkeley.cas.authentication.principal;

import org.jasig.cas.authentication.principal.RememberMeCredentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

import javax.validation.constraints.NotNull;

public class SurrogateUsernamePasswordCredentials extends UsernamePasswordCredentials implements RememberMeCredentials {
    /**
     * The username a surrogate becomes
     */
    @NotNull
    private String targetUsername;

    private boolean rememberMe = false;

    public String getTargetUsername() {
        return targetUsername;
    }

    public void setTargetUsername(String targetUsername) {
        this.targetUsername = targetUsername;
    }

    @Override
    public boolean isRememberMe() {
        return this.rememberMe;
    }

    @Override
    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
