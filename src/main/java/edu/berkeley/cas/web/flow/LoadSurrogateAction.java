package edu.berkeley.cas.web.flow;

import edu.berkeley.cas.authentication.principal.SurrogateUsernamePasswordCredentials;
import edu.berkeley.cas.authentication.service.SurrogateUsernamePasswordService;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.RememberMeCredentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.springframework.webflow.execution.RequestContext;

import javax.validation.constraints.NotNull;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class to support surrogate authentication selection in the CAS login web flow.
 */
class LoadSurrogateAction {
    @NotNull
    private SurrogateUsernamePasswordService surrogateUsernamePasswordService;

    /**
     * String that separates a target and username in a combined form
     */
    private String separator = "+";

    /**
     * load a map containing eligible accounts for this surrogate
     *
     * @param context The current webflow request context
     * @param credentials The current credentials
     */
    // Don't like this, but generics don't like me
    @SuppressWarnings("unchecked")
    public void load(final RequestContext context, final Credentials credentials) {
        java.util.Map<String, Object> referenceData = (Map<String, Object>) context.getFlowScope().get("referenceData", java.util.Map.class);
        if (credentials instanceof UsernamePasswordCredentials) {
            java.util.Map<String, String> surrogates = new LinkedHashMap<String, String>();
            for (String target : surrogateUsernamePasswordService.getSurrogateAccounts(((UsernamePasswordCredentials) credentials).getUsername())) {
                surrogates.put(target, target);
            }
            referenceData.put("surrogates", surrogates);
        }
    }

    /**
     * Check to see if surrogate list should be shown
     *
     * @param context The current webflow request context
     * @return String representation of boolean
     */
    public String doSurrogate(RequestContext context) {
        return context.getExternalContext().getRequestParameterMap().getBoolean("surrogate", false).toString();
    }

    public void buildSurrogatePrincipal(final RequestContext context, Credentials credentials) {
        if (credentials instanceof UsernamePasswordCredentials) {
            UsernamePasswordCredentials upc = (UsernamePasswordCredentials) credentials;
            String target = context.getExternalContext().getRequestParameterMap().get("surrogateTarget");
            if (target != null && !"".equals(target)) {
                upc.setUsername(target + separator + upc.getUsername());
            }
        }
    }

    /**
     * Converts a UsernamePasswordCredentials to a SurrogateUsernamePasswordCredentials if eligible
     * @param usernamePasswordCredentials Credentials to check and base new credentials upon
     * @return a new SurrogateUsernamePasswordCredential if eligible, otherwise the passed UsernamePasswordCredentials
     */
    public UsernamePasswordCredentials convertSurrogateCredentials(UsernamePasswordCredentials usernamePasswordCredentials) {
        if (!(usernamePasswordCredentials instanceof SurrogateUsernamePasswordCredentials) && usernamePasswordCredentials.getUsername().contains(this.separator)) {
            SurrogateUsernamePasswordCredentials surrogateUsernamePasswordCredentials = new SurrogateUsernamePasswordCredentials();

            String tUsername = usernamePasswordCredentials.getUsername();
            String targetUsername = tUsername.substring(0, tUsername.indexOf(this.separator));
            String username = tUsername.substring(tUsername.indexOf(this.separator) + 1);
            surrogateUsernamePasswordCredentials.setUsername(username);
            surrogateUsernamePasswordCredentials.setTargetUsername(targetUsername);
            if (usernamePasswordCredentials instanceof RememberMeCredentials) {
                surrogateUsernamePasswordCredentials.setRememberMe(((RememberMeCredentials)usernamePasswordCredentials).isRememberMe());
            }
            surrogateUsernamePasswordCredentials.setPassword(usernamePasswordCredentials.getPassword());

            return surrogateUsernamePasswordCredentials;
        }
        return usernamePasswordCredentials;
    }

    /**
     * Converts a SurrogateUsernamePasswordCredentials to a UsernamePasswordCredentials if eligible
     *
     * @param usernamePasswordCredentials Credentials to check and base a new UsernamePasswordCredentials upon
     * @return a new UsernamePasswordCredentials if the original was a SurrogateUsernamePasswordCredentials, otherwise the passed UsernamePasswordCredentials
     */
    public UsernamePasswordCredentials demoteSurrogateCredentials(UsernamePasswordCredentials usernamePasswordCredentials) {
        if (usernamePasswordCredentials instanceof SurrogateUsernamePasswordCredentials) {
            UsernamePasswordCredentials nUsernamePasswordCredentials = new UsernamePasswordCredentials();
            nUsernamePasswordCredentials.setUsername(usernamePasswordCredentials.getUsername());
            nUsernamePasswordCredentials.setPassword(usernamePasswordCredentials.getPassword());
            return nUsernamePasswordCredentials;
        }
        return usernamePasswordCredentials;
    }

    public void setSurrogateUsernamePasswordService(SurrogateUsernamePasswordService surrogateUsernamePasswordService) {
        this.surrogateUsernamePasswordService = surrogateUsernamePasswordService;
    }

    public void setSeparator(String separator) {
        this.separator = separator;
    }
}
