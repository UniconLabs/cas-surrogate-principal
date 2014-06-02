package edu.berkeley.cas.authentication.service;

/**
 * Service interface for surrogate authentication
 */
public interface SurrogateUsernamePasswordService {
    /**
     * Checks whether a surrogate can authenticate as a particular user
     *
     * @param username The username of the target principal
     * @param surrogate The username of the surrogate
     * @return true if the given surrogate can authenticate as the user
     */
    boolean canAuthenticateAs(String username, String surrogate);
}
