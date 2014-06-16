package edu.berkeley.cas.web.flow;

import edu.berkeley.cas.authentication.service.SurrogateUsernamePasswordService;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;
import org.springframework.webflow.execution.RequestContext;

import javax.validation.constraints.NotNull;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class to support surrogate authentication selection in the CAS login web flow.
 */
public class LoadSurrogateAction {
    @NotNull
    private SurrogateUsernamePasswordService surrogateUsernamePasswordService;

    private String separator = "+";

    /**
     * load a map containing eligible accounts for this surrogate
     *
     * @param context
     * @param credentials
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
     * @param context
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
        return;
    }

    public void setSurrogateUsernamePasswordService(SurrogateUsernamePasswordService surrogateUsernamePasswordService) {
        this.surrogateUsernamePasswordService = surrogateUsernamePasswordService;
    }

    public void setSeparator(String separator) {
        this.separator = separator;
    }
}
