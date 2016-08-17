package org.omnifaces.jaccprovider.jacc.policy;
import static java.util.Arrays.asList;
import static java.util.Collections.list;
import static org.omnifaces.jaccprovider.cdi.CdiUtils.getBeanReferenceExtra;
import static org.omnifaces.jaccprovider.jacc.AuthorizationRules.hasAccessViaRole;
import static org.omnifaces.jaccprovider.jacc.AuthorizationRules.hasAccessViaRoles;
import static org.omnifaces.jaccprovider.jacc.AuthorizationRules.isExcluded;
import static org.omnifaces.jaccprovider.jacc.AuthorizationRules.isUnchecked;
import static org.omnifaces.jaccprovider.jacc.configuration.TestPolicyConfigurationFactory.getCurrentPolicyConfiguration;

import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Map;

import org.omnifaces.jaccprovider.cdi.AuthorizationMechanism;
import org.omnifaces.jaccprovider.jacc.Caller;
import org.omnifaces.jaccprovider.jacc.RoleMapper;
import org.omnifaces.jaccprovider.jacc.SecurityConstraints;
import org.omnifaces.jaccprovider.jacc.configuration.TestPolicyConfiguration;
import org.omnifaces.jaccprovider.jacc.configuration.TestPolicyConfigurationPermissions;
 
public class DefaultPolicy extends Policy {
     
    private Policy previousPolicy = Policy.getPolicy();
     
    @Override
    public boolean implies(ProtectionDomain domain, Permission requestedPermission) {
             
        TestPolicyConfiguration policyConfiguration = getCurrentPolicyConfiguration();
        RoleMapper roleMapper = policyConfiguration.getRoleMapper();
        SecurityConstraints securityConstraints = policyConfiguration.getSecurityConstraints();
        
        List<Principal> currentUserPrincipals = asList(domain.getPrincipals());
        
        Principal callerPrincipal = roleMapper.getCallerPrincipalFromPrincipals(currentUserPrincipals);

        // Note: if caller principal
        boolean postAuthenticate = callerPrincipal != null && callerPrincipal.getName() != null;
        
        AuthorizationMechanism mechanism = getBeanReferenceExtra(AuthorizationMechanism.class);
        Caller caller = null;
        
        if (postAuthenticate) {
            caller = new Caller(
                callerPrincipal,
                roleMapper.getMappedRolesFromPrincipals(currentUserPrincipals),
                currentUserPrincipals);
        }
        
        if (mechanism != null) {
            Boolean authorizationOutcome = postAuthenticate? 
                mechanism.postAuthenticatePreAuthorize(requestedPermission, caller, securityConstraints) :
                mechanism.preAuthenticatePreAuthorize(requestedPermission, securityConstraints);
            
            if (authorizationOutcome != null) {
                return authorizationOutcome;
            }
        }
     
        if (isExcluded(securityConstraints.getExcludedPermissions(), requestedPermission)) {
            // Excluded permissions cannot be accessed by anyone
            return false;
        }
         
        if (isUnchecked(securityConstraints.getUncheckedPermissions(), requestedPermission)) {
            // Unchecked permissions are free to be accessed by everyone
            return true;
        }
        
        if (mechanism != null) {
            Boolean authorizationOutcome = postAuthenticate? 
                mechanism.postAuthenticatePreAuthorizeByRole(requestedPermission, caller, securityConstraints) :
                mechanism.preAuthenticatePreAuthorizeByRole(requestedPermission, securityConstraints);
            
            if (authorizationOutcome != null) {
                return authorizationOutcome;
            }
        }
         
        if (!roleMapper.isAnyAuthenticatedUserRoleMapped() && !currentUserPrincipals.isEmpty()) {
            // The "any authenticated user" role is not mapped, so available to anyone and the current
            // user is assumed to be authenticated (we assume that an unauthenticated user doesn't have any principals
            // whatever they are)
            if (hasAccessViaRole(securityConstraints.getPerRolePermissions(), "**", requestedPermission)) {
                // Access is granted purely based on the user being authenticated (the actual roles, if any, the user has it not important)
                return true;
            }
        }
         
        if (hasAccessViaRoles(securityConstraints.getPerRolePermissions(), roleMapper.getMappedRolesFromPrincipals(currentUserPrincipals), requestedPermission)) {
            // Access is granted via role. Note that if this returns false it doesn't mean the permission is not
            // granted. A role can only grant, not take away permissions.
            return true;
        }
         
        // Access not granted via any of the JACC maintained Permissions. Check the previous (default) policy.
        // Note: this is likely to be called in case it concerns a Java SE type permissions.
        // TODO: Should we not distinguish between JACC and Java SE Permissions at the start of this method? Seems
        //       very unlikely that JACC would ever say anything about a Java SE Permission, or that the Java SE
        //       policy says anything about a JACC Permission. Why are these two systems even combined in the first place?
        if (previousPolicy != null) {
            return previousPolicy.implies(domain, requestedPermission);
        }
         
        return false;
    }
 
    @Override
    public PermissionCollection getPermissions(ProtectionDomain domain) {
 
        Permissions permissions = new Permissions();
         
        TestPolicyConfiguration policyConfiguration = getCurrentPolicyConfiguration();
        RoleMapper roleMapper = policyConfiguration.getRoleMapper();
        SecurityConstraints securityConstraints = policyConfiguration.getSecurityConstraints();
         
        Permissions excludedPermissions = securityConstraints.getExcludedPermissions();
 
        // First get all permissions from the previous (original) policy
        if (previousPolicy != null) {
            collectPermissions(previousPolicy.getPermissions(domain), permissions, excludedPermissions);
        }
 
        // If there are any static permissions, add those next
        if (domain.getPermissions() != null) {
            collectPermissions(domain.getPermissions(), permissions, excludedPermissions);
        }
 
        // Thirdly, get all unchecked permissions
        collectPermissions(securityConstraints.getUncheckedPermissions(), permissions, excludedPermissions);
 
        // Finally get the permissions for each role *that the current user has*
        //
        // Note that the principles that are put into the ProtectionDomain object are those from the current user.
        // (for a Server application, passing in a Subject would have been more logical, but the Policy class was
        // made for Java SE with code-level security in mind)
        Map<String, Permissions> perRolePermissions = securityConstraints.getPerRolePermissions();
        for (String role : roleMapper.getMappedRolesFromPrincipals(domain.getPrincipals())) {
            if (perRolePermissions.containsKey(role)) {
                collectPermissions(perRolePermissions.get(role), permissions, excludedPermissions);
            }
        }
 
        return permissions;
    }
     
    @Override
    public PermissionCollection getPermissions(CodeSource codesource) {
 
        Permissions permissions = new Permissions();
         
        TestPolicyConfigurationPermissions policyConfiguration = getCurrentPolicyConfiguration();
        SecurityConstraints securityConstraints = policyConfiguration.getSecurityConstraints();
        
        Permissions excludedPermissions = securityConstraints.getExcludedPermissions();
 
        // First get all permissions from the previous (original) policy
        if (previousPolicy != null) {
            collectPermissions(previousPolicy.getPermissions(codesource), permissions, excludedPermissions);
        }
 
        // Secondly get the static permissions. Note that there are only two sources possible here, without
        // knowing the roles of the current user we can't check the per role permissions.
        collectPermissions(securityConstraints.getUncheckedPermissions(), permissions, excludedPermissions);
 
        return permissions;
    }
     
    /**
     * Copies permissions from a source into a target skipping any permission that's excluded.
     * 
     * @param sourcePermissions
     * @param targetPermissions
     * @param excludedPermissions
     */
    private void collectPermissions(PermissionCollection sourcePermissions, PermissionCollection targetPermissions, Permissions excludedPermissions) {
         
        boolean hasExcludedPermissions = excludedPermissions.elements().hasMoreElements();
         
        for (Permission permission : list(sourcePermissions.elements())) {
            if (!hasExcludedPermissions || !isExcluded(excludedPermissions, permission)) {
                targetPermissions.add(permission);
            }
        }
    }
     
}