package com.onndoo.security.servlet;

import java.io.IOException;

import org.glassfish.exousia.modules.def.DefaultPolicyConfiguration;
import org.glassfish.exousia.spi.PrincipalMapper;

import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.jacc.PolicyConfiguration;
import jakarta.security.jacc.PolicyConfigurationFactory;
import jakarta.security.jacc.PolicyContextException;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Test Servlet that prints out the name of the authenticated caller and whether
 * this caller is in any of the roles {foo, bar, kaz}
 * 
 *
 */
@WebServlet("/protectedServlet")
@ServletSecurity(@HttpConstraint(rolesAllowed = "foo"))
public class ProtectedServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    @Inject
    private SecurityContext securityContext;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.getWriter().write("This is a servlet \n");

        String webName = null;
        if (request.getUserPrincipal() != null) {
            webName = request.getUserPrincipal().getName();
        }

        response.getWriter().write("web username: " + webName + "\n");

        response.getWriter().write("web user has role \"foo\": " + request.isUserInRole("foo") + "\n");
        response.getWriter().write("web user has role \"bar\": " + request.isUserInRole("bar") + "\n");
        response.getWriter().write("web user has role \"kaz\": " + request.isUserInRole("kaz") + "\n");
        
        if (securityContext != null && securityContext.getCallerPrincipal() != null) {
            if (securityContext.isCallerInRole("admin")) {
                System.out.println("LLL");
            } else {
            	System.out.println("ZZZ");
            }
        } else {
            // Handle the case where security context or caller is null
            throw new SecurityException("User is not authenticated.");
        }
        
        String contextName = null;
        if (securityContext.getCallerPrincipal() != null) {
            contextName = securityContext.getCallerPrincipal().getName();
        }
        
        response.getWriter().write("context username: " + contextName + "\n");
        
        //response.getWriter().write("context user has role \"foo\": " + securityContext.isCallerInRole("foo") + "\n");
        //response.getWriter().write("context user has role \"bar\": " + securityContext.isCallerInRole("bar") + "\n");
        //response.getWriter().write("context user has role \"kaz\": " + securityContext.isCallerInRole("kaz") + "\n");
        
        PolicyConfiguration policyConfiguration =
                getPolicyConfigurationFactory().getPolicyConfiguration();
                
        System.out.println(policyConfiguration);
        PrincipalMapper roleMapper = ((DefaultPolicyConfiguration) policyConfiguration)
            .getRoleMapper();
        
        System.out.println(roleMapper);
        //response.getWriter().write("has access " + securityContext.hasAccessToWebResource("/foo/bar"));
        
    }
    
    private PolicyConfigurationFactory getPolicyConfigurationFactory() {
        try {
            return PolicyConfigurationFactory.getPolicyConfigurationFactory();
        } catch (ClassNotFoundException | PolicyContextException e) {
            throw new IllegalStateException(e);
        }
    }

}