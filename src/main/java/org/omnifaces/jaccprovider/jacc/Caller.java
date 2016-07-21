package org.omnifaces.jaccprovider.jacc;

import java.security.Principal;
import java.util.List;

public class Caller {

    private Principal callerPrincipal;
    private List<String> roles;
    private List<Principal> unmappedPrincipals;
    
    public Caller(Principal callerPrincipal, List<String> roles, List<Principal> unmappedPrincipals) {
        this.callerPrincipal = callerPrincipal;
        this.roles = roles;
        this.unmappedPrincipals = unmappedPrincipals;
    }

    public Principal getCallerPrincipal() {
        return callerPrincipal;
    }

    public List<String> getRoles() {
        return roles;
    }

    public List<Principal> getUnmappedPrincipals() {
        return unmappedPrincipals;
    }

}
