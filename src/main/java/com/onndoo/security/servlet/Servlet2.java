package com.onndoo.security.servlet;

import java.io.IOException;

import jakarta.security.enterprise.authentication.mechanism.http.BasicAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.CustomFormAuthenticationMechanismDefinition;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.HttpConstraint;
import jakarta.servlet.annotation.ServletSecurity;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//@BasicAuthenticationMechanismDefinition(realmName = "MyRealm")
@WebServlet(urlPatterns = "/servlet2")
@ServletSecurity(value = @HttpConstraint(rolesAllowed = "myRole"))
public class Servlet2 extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        response.getWriter().write("web username: " +  request.getUserPrincipal().getName() + "\n");

        response.getWriter().write("CAller has Role myRole : " + request.isUserInRole("myRole") + "\n");
        
    }
}
