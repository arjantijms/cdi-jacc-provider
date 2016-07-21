package org.omnifaces.jaccprovider.jacc;

import static java.util.Collections.list;
import static java.util.stream.Collectors.toList;

import java.security.Permission;
import java.security.Permissions;
import java.util.List;
import java.util.Map;

public class AuthorizationRules {
    
    public static boolean isExcluded(Permissions excludedPermissions, Permission requestedPermission) {
        if (excludedPermissions.implies(requestedPermission)) {
            return true;
        }
         
        for (Permission excludedPermission : list(excludedPermissions.elements())) {
            if (requestedPermission.implies(excludedPermission)) {
                return true;
            }
        }
         
        return false;
    }
     
    public static boolean isUnchecked(Permissions uncheckedPermissions, Permission requestedPermission) {
        return uncheckedPermissions.implies(requestedPermission);
    }
     
    public static boolean hasAccessViaRoles(Map<String, Permissions> perRolePermissions, List<String> roles, Permission requestedPermission) {
        for (String role : roles) {
            if (hasAccessViaRole(perRolePermissions, role, requestedPermission)) {
                return true;
            }
        }
         
        return false;
    }
     
    public static boolean hasAccessViaRole(Map<String, Permissions> perRolePermissions, String role, Permission requestedPermission) {
        return perRolePermissions.containsKey(role) && perRolePermissions.get(role).implies(requestedPermission);
    }
    
    public static List<String> getRequiredRoles(Map<String, Permissions> perRolePermissions, Permission requestedPermission) {
        return perRolePermissions
                    .entrySet().stream()
                    .filter(entry -> entry.getValue().implies(requestedPermission))
                    .map(e -> e.getKey())
                    .collect(toList());
    }

}
