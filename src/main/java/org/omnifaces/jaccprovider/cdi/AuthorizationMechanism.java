package org.omnifaces.jaccprovider.cdi;

import java.security.Permission;

import org.omnifaces.jaccprovider.jacc.Caller;
import org.omnifaces.jaccprovider.jacc.SecurityConstraints;

public interface AuthorizationMechanism {
    
    default Boolean preAuthenticatePreAuthorize(Permission requestedPermission, SecurityConstraints securityConstraints) {
        return null;
    }
    
    default Boolean preAuthenticatePreAuthorizeByRole(Permission requestedPermission, SecurityConstraints securityConstraints) {
        return null;
    }

    default Boolean postAuthenticatePreAuthorize(Permission requestedPermission, Caller caller, SecurityConstraints securityConstraints) {
        return null;
    }
    
    default Boolean postAuthenticatePreAuthorizeByRole(Permission requestedPermission, Caller caller, SecurityConstraints securityConstraints) {
        return null;
    }
}
