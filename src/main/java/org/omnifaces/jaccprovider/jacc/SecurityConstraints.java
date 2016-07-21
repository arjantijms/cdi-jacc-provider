package org.omnifaces.jaccprovider.jacc;

import java.security.Permissions;
import java.util.HashMap;
import java.util.Map;

public class SecurityConstraints {

    private Permissions excludedPermissions = new Permissions();
    private Permissions uncheckedPermissions = new Permissions();
    private Map<String, Permissions> perRolePermissions = new HashMap<String, Permissions>();

    public Permissions getExcludedPermissions() {
        return excludedPermissions;
    }

    public Permissions getUncheckedPermissions() {
        return uncheckedPermissions;
    }

    public Map<String, Permissions> getPerRolePermissions() {
        return perRolePermissions;
    }
    
    public void setExcludedPermissions(Permissions excludedPermissions) {
        this.excludedPermissions = excludedPermissions;
    }

    public void setUncheckedPermissions(Permissions uncheckedPermissions) {
        this.uncheckedPermissions = uncheckedPermissions;
    }

    public void setPerRolePermissions(Map<String, Permissions> perRolePermissions) {
        this.perRolePermissions = perRolePermissions;
    }
    
    public void clear() {
        excludedPermissions = new Permissions();
        uncheckedPermissions = new Permissions();
        perRolePermissions.clear();
    }

}
