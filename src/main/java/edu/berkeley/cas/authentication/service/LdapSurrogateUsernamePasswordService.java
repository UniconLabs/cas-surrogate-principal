package edu.berkeley.cas.authentication.service;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;

import javax.annotation.PostConstruct;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;
import javax.validation.constraints.NotNull;
import java.util.*;

/**
 * Surrogate username password service that uses LDAP. This implementation uses generic interfaces that should be
 * usable by any LDAP system. More efficient implementation can be written that take advantage of system specfic
 * features like virtual attributes.
 */
public class LdapSurrogateUsernamePasswordService implements SurrogateUsernamePasswordService {
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

    /**
     * Username attribute. The LDAP attribute that will be returned as the username for accounts.
     */
    @Value("${ldap.surrogate.attribute.username:uid}")
    private String usernameAttribute = "uid";

    /**
     * Group member attribute. The attribute that stores the group membership in a group.
     */
    @Value("${ldap.surrogate.attribute.member:member}")
    private String memberAttribute = "member";

    /**
     * Filter to find a Group that contains both the surrogate and the target
     * <p/>
     * %s will be replaced with the surrogate DN
     * %t will be replaced with the target DN
     */
    @Value("${ldap.surrogate.filter.group:(&(member=%s)(member=%t))}")
    private String groupSearchFilter = "(&(member=%s)(member=%t))";

    @Autowired(required = false)
    private LdapTemplate ldapTemplate;

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

    @Override
    public boolean canAuthenticateAs(String username, String surrogate) {
        // get the dn of the surrogate user
        String filter = StringUtils.replace(surrogateUserSearchFilter, "%u", surrogate);
        List surrogateUser = ldapTemplate.search("", filter, dnMapper);

        // get the dn of the user
        filter = StringUtils.replace(targetUserSearchFilter, "%u", username);
        List userList = ldapTemplate.search("", filter, dnMapper);

        if ((surrogateUser != null && surrogateUser.size() > 0) &&
                (userList != null && userList.size() > 0)) {
            String ldapUser = userList.get(0).toString();
            String ldapSurrogate = surrogateUser.get(0).toString();

            // find any group that has the user and surrogate as members
            // If a group is found, then return true.
            filter = StringUtils.replace(groupSearchFilter, "%t", ldapUser);
            filter = StringUtils.replace(filter, "%s", ldapSurrogate);
            List groups = ldapTemplate.search("", filter, dnMapper);

            if (groups != null && groups.size() > 0) {
                return true;
            }
        }

        return false;
    }

    @Override
    public Collection<String> getSurrogateAccounts(String surrogate) {
        LinkedHashSet<String> accounts = new LinkedHashSet<String>();
        accounts.add(surrogate);

        // get the DN of the surrogate, get all the users in the same groups as the surrogate, then get a list of
        // usernames for those users that are eligible surrogate targets
        Collection<String> correctUsers = getCorrectUsers(getAllUsers(getUserDn(surrogate)));
        if (correctUsers != null) {
            // sort the list of username
            List<String> nCorrectUsers = new ArrayList<String>(correctUsers);
            Collections.sort(nCorrectUsers);
            accounts.addAll(nCorrectUsers);
        }

        return accounts;
    }

    private String getUserDn(String username) {
        String nFilter = surrogateUserSearchFilter.replaceAll("%u", username);
        List results = ldapTemplate.search(baseDN, nFilter, SearchControls.SUBTREE_SCOPE, dnMapper);
        if (results.size() > 0) {
            return results.get(0).toString();
        }
        return null;
    }

    private Collection<String> getAllUsers(String userDn) {
        HashSet<String> users = new HashSet<String>();

        String filter = userGroupFilter.replaceAll("%d", userDn);
        List results = ldapTemplate.search(baseDN, filter, SearchControls.SUBTREE_SCOPE, new String[]{"member"}, new ContextMapper() {
            @Override
            public Object mapFromContext(Object ctx) {
                if (ctx instanceof DirContextOperations) {
                    return ((DirContextOperations) ctx).getAttributeSortedStringSet(memberAttribute);
                }
                throw new IllegalStateException();
            }
        });

        for (Object result : results) {
            if (result instanceof Set) {
                users.addAll((Set) result);
            }
        }

        return users;
    }

    private Collection<String> getCorrectUsers(Collection<String> allUsers) {
        HashSet<String> usernames = new HashSet<String>();

        String filter = targetUserSearchFilter.replaceAll("%u", "*");
        for (String dn : allUsers) {
            List results = ldapTemplate.search(dn, filter, SearchControls.OBJECT_SCOPE, new String[]{usernameAttribute}, new ContextMapper() {
                @Override
                public Object mapFromContext(Object ctx) {
                    if (ctx instanceof DirContextOperations) {
                        return ((DirContextOperations) ctx).getAttributeSortedStringSet(usernameAttribute);
                    }
                    throw new IllegalStateException();
                }
            });
            if (results.size() > 0) {
                Object result = results.get(0);
                if (result instanceof Set) {
                    usernames.addAll((Set) result);
                }
            }
        }

        return usernames;
    }

    public void setContextSource(ContextSource contextSource) {
        this.contextSource = contextSource;
    }

    public void setBaseDN(String baseDN) {
        this.baseDN = baseDN;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    public void setUserGroupFilter(String userGroupFilter) {
        this.userGroupFilter = userGroupFilter;
    }

    public void setSurrogateUserSearchFilter(String surrogateUserSearchFilter) {
        this.surrogateUserSearchFilter = surrogateUserSearchFilter;
    }

    public void setTargetUserSearchFilter(String targetUserSearchFilter) {
        this.targetUserSearchFilter = targetUserSearchFilter;
    }

    public void setUsernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
    }
}
