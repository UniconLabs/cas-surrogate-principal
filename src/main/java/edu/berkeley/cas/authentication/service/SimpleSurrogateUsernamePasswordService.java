package edu.berkeley.cas.authentication.service;

import java.util.Collection;
import java.util.Arrays;

/**
 * A simple implementation of SurrogateUsernamePasswordService
 */
public class SimpleSurrogateUsernamePasswordService implements SurrogateUsernamePasswordService {
    @Override
    public boolean canAuthenticateAs(String username, String surrogate) {
        return username.equals(surrogate);
    }

    @Override
    public Collection<String> getSurrogateAccounts(String surrogate) {
        return Arrays.asList(surrogate);
    }
}
