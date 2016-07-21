# cdi-jacc-provider

JACC provider that uses CDI to delegate to code in the application.

This allows a Java EE application to influence the authorization process by providing custom logic with a minimal of fuzz.

# Building

The JACC provider can be build using:

``mvn clean package``

# Installing

A JACC provider needs to be installed in a server specific way. E.g. for Payara it needs to be copied to the [payara home]/lib folder. For example assuming Payara 4.1.1.162 installed in /opt:

``cp target/cdi-jacc-provider-0.1-SNAPSHOT.jar /opt/payara-4.1.1.162/glassfish/lib/``

Then the following needs to be added to /opt/payara-4.1.1.162/glassfish//domains/domain1/config/domain.xml below the ``<security-service>`` element:

``<jacc-provider policy-provider="org.omnifaces.jaccprovider.jacc.policy.DefaultPolicy" name="custom" policy-configuration-factory-provider="org.omnifaces.jaccprovider.jacc.configuration.TestPolicyConfigurationFactory"></jacc-provider>``

And finally a ``jacc`` attribute needs to be added to this element so that it looks as follows:

``<security-service jacc="custom">``

# Using

```java
@ApplicationScoped
public class CustomAuthorizationMechanism implements AuthorizationMechanism {
    
    @Override
    public Boolean postAuthenticatePreAuthorizeByRole(Permission requestedPermission, Caller caller, SecurityConstraints securityConstraints) {
        // Return TRUE, FALSE, or NULL here
        // TRUE; requested permission granted
        // FALSE; requested permission not granted
        // null; "do nothing"; let default authorization algorithm handle this
        return null;
    }
}
        
```

# Notes

This is an experimental prototype which may be moved and adapted to JSR 375.
