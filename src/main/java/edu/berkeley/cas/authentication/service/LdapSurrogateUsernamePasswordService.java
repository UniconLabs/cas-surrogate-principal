package edu.berkeley.cas.authentication.service;

import org.springframework.ldap.core.ContextSource;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import javax.naming.ldap.LdapName;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;

/**
 * Surrogate username password service that uses LDAP
 */
public class LdapSurrogateUsernamePasswordService implements SurrogateUsernamePasswordService {
    @NotNull
    ContextSource contextSource;

    String baseDN = "";
    String userFilter = "(uid=%u)";
    
    @Value("${ldap.surrogate.search.filter}")
    private String surrogateSearchFilter;
    
    @Value("${ldap.user.search.filter}")
    private String userSearchFilter;
    
    @Value("${ldap.group.search.filter}")
    private String groupSearchFilter;
    
    @Autowired
    private LdapTemplate ldapTemplate;
    
    @Override
    public boolean canAuthenticateAs(String username, String surrogate) {
        try {                
            ContextMapper mapper = new AbstractContextMapper() {
                @Override
                public Object doMapFromContext( DirContextOperations ctx) {
                    return ctx.getDn();
                }
            };
                    
            // get the dn of the surrogate user
            String filter = StringUtils.replace( surrogateSearchFilter, "?", surrogate);
            List surrogateUser = ldapTemplate.search( "", filter, mapper);
            
            // get the dn of the user
            filter = StringUtils.replace( userSearchFilter, "?", username);
            List userList = ldapTemplate.search( "", filter, mapper);
            
            if(( surrogateUser != null && surrogateUser.size() > 0) && 
                    ( userList != null && userList.size() > 0)) {
                LdapName ldapUser = (LdapName)userList.get(0);
                LdapName ldapSurrogate = (LdapName)surrogateUser.get(0);
                
                // find any group that has the user and surrogate as members
                // If a group is found, then return true.
                filter = StringUtils.replace( groupSearchFilter, "$1", ldapUser.toString());
                filter = StringUtils.replace( filter, "$2", ldapSurrogate.toString());
                List groups = ldapTemplate.search( "", filter, mapper);
            
                if( groups != null && groups.size() > 0) {
                    return true;
                }
            }
        }
        catch( Exception e) {
        }
       
        return false;
    }

    @Override
    public Collection<String> getSurrogateAccounts(String surrogate) {
        LinkedHashSet<String> accounts = new LinkedHashSet<String>();
        accounts.add(surrogate);
        return accounts;
    }
}
