package edu.berkeley.cas.authentication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;

import javax.annotation.PostConstruct;
import javax.naming.directory.SearchControls;
import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;

abstract public class AbstractLdapSurrogateUsernamePasswordService implements SurrogateUsernamePasswordService{
    @NotNull
    private ContextSource contextSource;

    /**
     * base DN for searching for surrogate
     */
    private String baseDN = "";

    /**
     * Filter to use to find a user eligible to become a surrogate
     * <p/>
     * %u will be replaced with the username
     */
    @Value("${ldap.surrogate.filter.user:(uid=%u)}")
    private String surrogateUserSearchFilter = "(uid=%u)";

    /**
     * Filter to use to find a user eligible to be a target for a surrogate
     * <p/>
     * %u will be replaced by the username
     */
    @Value("${ldap.surrogate.filter.target:(uid=%u)}")
    private String targetUserSearchFilter = "(uid=%u)";

    /**
     * Filter to find the Group DNs for a user DN.
     * <p/>
     * %d will be replaced with the user's DN
     */
    @Value("${ldap.surrogate.filter.userGroup:(member=%d)}")
    private String userGroupFilter = "(member=%d)";

    @Autowired(required = false)
    private LdapTemplate ldapTemplate;

    /**
     * Username attribute. The LDAP attribute that will be returned as the username for accounts.
     */
    @Value("${ldap.surrogate.attribute.username:uid}")
    private String usernameAttribute = "uid";

    @PostConstruct
    void setup() {
        if (this.ldapTemplate == null) {
            this.ldapTemplate = new LdapTemplate(this.contextSource);
        }
    }

    private final ContextMapper dnMapper = new AbstractContextMapper() {
        @Override
        protected Object doMapFromContext(DirContextOperations ctx) {
            return ctx.getDn();
        }
    };

    protected String getUserDn(String username) {
        String nFilter = surrogateUserSearchFilter.replaceAll("%u", username);
        List results = ldapTemplate.search(baseDN, nFilter, SearchControls.SUBTREE_SCOPE, dnMapper);
        if (results.size() > 0) {
            return results.get(0).toString();
        }
        return null;
    }

    public void setContextSource(ContextSource contextSource) {
        this.contextSource = contextSource;
    }

    public void setBaseDN(String baseDN) {
        this.baseDN = baseDN;
    }

    public void setSurrogateUserSearchFilter(String surrogateUserSearchFilter) {
        this.surrogateUserSearchFilter = surrogateUserSearchFilter;
    }

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public void setUsernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
    }

    public ContextSource getContextSource() {
        return contextSource;
    }

    public String getBaseDN() {
        return baseDN;
    }

    public String getSurrogateUserSearchFilter() {
        return surrogateUserSearchFilter;
    }

    public LdapTemplate getLdapTemplate() {
        return ldapTemplate;
    }

    public String getUsernameAttribute() {
        return usernameAttribute;
    }

    public ContextMapper getDnMapper() {
        return dnMapper;
    }

    public String getTargetUserSearchFilter() {
        return targetUserSearchFilter;
    }

    public void setTargetUserSearchFilter(String targetUserSearchFilter) {
        this.targetUserSearchFilter = targetUserSearchFilter;
    }

    public String getUserGroupFilter() {
        return userGroupFilter;
    }

    public void setUserGroupFilter(String userGroupFilter) {
        this.userGroupFilter = userGroupFilter;
    }
}
