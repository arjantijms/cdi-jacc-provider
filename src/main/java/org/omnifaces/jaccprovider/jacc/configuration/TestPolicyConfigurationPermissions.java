package org.omnifaces.jaccprovider.jacc.configuration;
import java.security.Permission;
import java.security.Permissions;

import javax.security.jacc.PolicyContextException;

import org.omnifaces.jaccprovider.jacc.SecurityConstraints;
 
public abstract class TestPolicyConfigurationPermissions extends TestPolicyConfigurationBase {
    
    private SecurityConstraints securityConstraints = new SecurityConstraints();

    public TestPolicyConfigurationPermissions(String contextID) {
        super(contextID);
    }
 
    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        securityConstraints.getExcludedPermissions().add(permission);
    }
 
    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        securityConstraints.getUncheckedPermissions().add(permission);
    }
 
    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        securityConstraints.getPerRolePermissions()
                           .computeIfAbsent(roleName, e -> new Permissions())
                           .add(permission);
    }
     
    @Override
    public void delete() throws PolicyContextException {
        securityConstraints.clear();
    }
 
    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        securityConstraints.setExcludedPermissions(new Permissions());
    }
    
    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        securityConstraints.setUncheckedPermissions(new Permissions());
    }

    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        if (securityConstraints.getPerRolePermissions().containsKey(roleName)) {
            securityConstraints.getPerRolePermissions().remove(roleName);
        } else if ("*".equals(roleName)) {
            securityConstraints.getPerRolePermissions().clear();
        }
    }
    
    public SecurityConstraints getSecurityConstraints() {
        return securityConstraints;
    }
 
}