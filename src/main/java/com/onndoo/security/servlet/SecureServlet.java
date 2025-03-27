package com.onndoo.security.servlet;

import java.io.IOException;

import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;



//@BasicAuthenticationMechanismDefinition(realmName = "MyRealm")
@ServletSecurity(value = @HttpConstraint(rolesAllowed = {"g1", "foo"} )) 

@WebServlet(urlPatterns = "/SecureServlet")
public class SecureServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Inject
	SecurityContext securityContext;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		
		response.getWriter().write("This is a servlet \n");
        
        System.out.println(securityContext.getCallerPrincipal().getName());
        
        
        String webName = null;
        if (request.getUserPrincipal() != null) {
            webName = request.getUserPrincipal().getName();
        }

        response.getWriter().write("web username: " + webName + "\n");
        
        
        
       
        
        boolean hasAccessToFooBar = request.isUserInRole("/foo/bar");
        
        System.out.println("===============================");

        boolean hasAccessToFooxBar = request.isUserInRole("/foox/bar");
        System.out.println("===============================");
		System.out.println(hasAccessToFooBar);
		System.out.println(hasAccessToFooxBar);
		response.getWriter().println("Has access to /foo/bar: " + hasAccessToFooBar);
        response.getWriter().println("Has access to /foox/bar: " + hasAccessToFooxBar);

        
        String contextName = null;
        if (securityContext.getCallerPrincipal() != null) {
            contextName = securityContext.getCallerPrincipal().getName();
        }
        
        response.getWriter().write("context username: " + contextName + "\n");
        //response.getWriter().write("has access " + securityContext.hasAccessToWebResource("/protectedServlet", "GET") + "\n");
        boolean hasAccessToFooBar1 = securityContext.hasAccessToWebResource("/foo333", "GET");
        response.getWriter().write("context user has role \"foo\": " + securityContext.isCallerInRole("foo") + "\n");
        //response.getWriter().write("context user has role \"bar\": " + securityContext.isCallerInRole("barw") + "\n");
        //response.getWriter().write("context user has role \"kaz\": " + securityContext.isCallerInRole("kazw") + "\n");
        
        
        //boolean hasAccessToFooBar1 = securityContext.hasAccessToWebResource("/foo/bar", "GET");
        // boolean hasAccessToFooxBar2 = securityContext.hasAccessToWebResource("/foox/bar", "GET");

		if (!hasAccessToFooBar) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
        if (!hasAccessToFooxBar) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
	}

}
