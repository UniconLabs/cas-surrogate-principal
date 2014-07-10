package edu.berkeley.cas.authentication.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextOperations;

import javax.naming.directory.SearchControls;
import java.util.*;

/**
 * Surrogate username password service that uses LDAP and filters from the target user perspective. This implementation
 * uses generic interfaces that should be usable by any LDAP system. More efficient implementation can be written that
 * take advantage of system specfic features like virtual attributes.
 */
public class UserPerspectiveLdapSurrogateUsernamePasswordService extends AbstractLdapSurrogateUsernamePasswordService {
    /**
     * Filter to use to find a user eligible to be a target for a surrogate
     * <p/>
     * %u will be replaced by the username
     */
    @Value("${ldap.surrogate.filter.target:(uid=%u)}")
    private String targetUserSearchFilter = "(uid=%u)";

    @Value("${ldap.surrogate.attribute.target:targetGroup}")
    private String targetGroupAttribute = "targetGroup";

    /**
     * Filter to find the Group DNs for a user DN.
     * <p/>
     * %d will be replaced with the user's DN
     */
    @Value("${ldap.surrogate.filter.userGroup:(member=%d)}")
    private String userGroupFilter = "(member=%d)";

    /**
     * Filter to find targets for a group DN
     *
     * %t will be replaced with a group DN
     */
    @Value("${ldap.surrogate.filter.targetGroup:(targetGroup=%t)}")
    private String targetGroupFilter = "(targetGroup=%t)";

    @Override
    public boolean canAuthenticateAs(String username, String surrogate) {
        if (username.equals(surrogate)) {
            return true;
        }

        String sfilter = getSurrogateUserSearchFilter().replaceAll("%u", surrogate);
        String surrogateUser = getLdapTemplate().search(getBaseDN(), sfilter, getDnMapper()).get(0).toString();

        String tfilter = getTargetUserSearchFilter().replaceAll("%u", username);
        List targetUserResults = getLdapTemplate().search(getBaseDN(), tfilter, SearchControls.SUBTREE_SCOPE, new String[]{targetGroupAttribute}, new ContextMapper() {
            @Override
            public Object mapFromContext(Object ctx) {
                if (ctx instanceof DirContextOperations) {
                    return ((DirContextOperations) ctx).getAttributeSortedStringSet(targetGroupAttribute);
                }
                throw new IllegalStateException();
            }
        });

        String gFilter = getUserGroupFilter().replaceAll("%d", surrogateUser);
        for (Object result: targetUserResults) {
            if (result instanceof Set) {
                for (String dn: (Set<String>)result) {
                    List groupResults = getLdapTemplate().search(dn, gFilter, SearchControls.OBJECT_SCOPE, getDnMapper());
                    if (groupResults != null && groupResults.size() > 0) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    @Override
    public Collection<String> getSurrogateAccounts(String surrogate) {
        LinkedHashSet<String> accounts = new LinkedHashSet<String>();
        accounts.add(surrogate);

        String userDn = getUserDn(surrogate);
        if (userDn != null && !"".equals(userDn)) {
            Collection<String> groups = getUserGroups(userDn);
            if (groups.size() > 0) {
                StringBuffer gQuery = new StringBuffer();
                for (String groupDn : groups) {
                    Collection<String> targets = getTargetsForGroup(groupDn);
                    if (targets.size() > 0) {
                        accounts.addAll(targets);
                    }
                }
            }
        }

        return accounts;
    }

    private Collection<String> getTargetsForGroup(String groupDn) {
        Set<String> targets = new HashSet<String>();

        String filter = targetGroupFilter.replaceAll("%t", groupDn);
        List results = getLdapTemplate().search(getBaseDN(), filter, SearchControls.SUBTREE_SCOPE, new String[]{getUsernameAttribute()}, new ContextMapper() {
            @Override
            public Object mapFromContext(Object ctx) {
                if (ctx instanceof DirContextOperations) {
                    return ((DirContextOperations) ctx).getAttributeSortedStringSet(getUsernameAttribute());
                }
                throw new IllegalStateException();
            }
        });

        for (Object result: results) {
            if (result instanceof Collection) {
                targets.addAll((Collection<? extends String>) result);
            }
        }


        return targets;
    }

    private Collection<String> getUserGroups(String surrogateDn) {
        Set<String> groups = new HashSet<String>();

        String filter = userGroupFilter.replaceAll("%d", surrogateDn);
        List results = getLdapTemplate().search(getBaseDN(), filter, SearchControls.SUBTREE_SCOPE, new String[]{"dn"}, getDnMapper());
        for (Object o : results) {
            groups.add(o.toString());
        }
        return groups;
    }

    private Collection<String> getEligibleGroups(String target) {
        Set<String> eligible = new HashSet<String>();

        String filter = targetUserSearchFilter.replaceAll("%u", target);
        List results = getLdapTemplate().search(getBaseDN(), filter, SearchControls.SUBTREE_SCOPE, new String[]{targetGroupAttribute}, new ContextMapper() {
            @Override
            public Object mapFromContext(Object ctx) {
                return null;
            }
        });

        return eligible;
    }

    public void setTargetUserSearchFilter(String targetUserSearchFilter) {
        this.targetUserSearchFilter = targetUserSearchFilter;
    }

    public void setTargetGroupFilter(String targetGroupFilter) {
        this.targetGroupFilter = targetGroupFilter;
    }

    public void setTargetGroupAttribute(String targetGroupAttribute) {
        this.targetGroupAttribute = targetGroupAttribute;
    }

    public void setUserGroupFilter(String userGroupFilter) {
        this.userGroupFilter = userGroupFilter;
    }
}
