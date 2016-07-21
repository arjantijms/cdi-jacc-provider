package org.omnifaces.jaccprovider.jacc.configuration;
import javax.security.jacc.PolicyContextException;

import org.omnifaces.jaccprovider.jacc.RoleMapper;
 
public class TestPolicyConfiguration extends TestPolicyConfigurationPermissions {
 
    public TestPolicyConfiguration(String contextID) {
        super(contextID);
    }
     
    private RoleMapper roleMapper;
 
    @Override
    public void commit() throws PolicyContextException {
        roleMapper = new RoleMapper(getContextID(), getSecurityConstraints().getPerRolePermissions().keySet());
    }
     
    public RoleMapper getRoleMapper() {
        return roleMapper;
    }
 
}