package edu.berkeley.cas.authentication.service;

import org.springframework.ldap.core.ContextSource;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.LinkedHashSet;

/**
 * Surrogate username password service that uses LDAP
 */
public class LdapSurrogateUsernamePasswordService implements SurrogateUsernamePasswordService {
    @NotNull
    ContextSource contextSource;

    String baseDN = "";
    String userFilter = "(uid=%u)";
    @Override
    public boolean canAuthenticateAs(String username, String surrogate) {
        return false;
    }

    @Override
    public Collection<String> getSurrogateAccounts(String surrogate) {
        LinkedHashSet<String> accounts = new LinkedHashSet<String>();
        accounts.add(surrogate);
        return accounts;
    }
}
