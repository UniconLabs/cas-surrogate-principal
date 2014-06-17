package edu.berkeley.cas.authentication.principal;

import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

import javax.validation.constraints.NotNull;

public class SurrogateUsernamePasswordCredentials extends UsernamePasswordCredentials {
    /**
     * The username a surrogate becomes
     */
    @NotNull
    private String targetUsername;

    public String getTargetUsername() {
        return targetUsername;
    }

    public void setTargetUsername(String targetUsername) {
        this.targetUsername = targetUsername;
    }
}
