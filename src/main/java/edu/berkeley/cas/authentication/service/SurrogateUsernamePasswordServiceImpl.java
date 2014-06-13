package edu.berkeley.cas.authentication.service;

import java.util.Collection;
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
 *
 * 
 */
public class SurrogateUsernamePasswordServiceImpl implements SurrogateUsernamePasswordService {

    @Value("${ldap.surrogate.search.filter}")
    private String surrogateSearchFilter;
    
    @Value("${ldap.user.search.filter}")
    private String userSearchFilter;
    
    @Value("${ldap.group.search.filter}")
    private String groupSearchFilter;
    
    @Autowired
    private LdapTemplate ldapTemplate;
    
    
    /**
     * Checks whether a surrogate can authenticate as a particular user
     *
     * @param username The username of the target principal
     * @param surrogate The username of the surrogate
     * @return true if the given surrogate can authenticate as the user
     */
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
    
    /**
     * 
     * @param surrogate
     * @return 
     */
    @Override
    public Collection<String> getSurrogateAccounts(String surrogate) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
