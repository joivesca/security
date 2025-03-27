package com.onndoo.security.config;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.credential.Password;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.security.enterprise.identitystore.IdentityStoreHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;

@ApplicationScoped
public class MyAuthenticationMechanism implements HttpAuthenticationMechanism {

	@Inject
    private IdentityStore identityStore;
	
	 @Override
	    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext context) {
		 
	        String authorizationHeader = request.getHeader("Authorization");
	        
	        if (authorizationHeader != null && authorizationHeader.startsWith("Basic")) {
	            // Decodifica las credenciales de Basic Auth
	            String base64Credentials = authorizationHeader.substring("Basic".length()).trim();
	            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
	            String[] values = credentials.split(":", 2);
	            String username = values[0];
	            String password = values[1];

	            // Valida las credenciales con IdentityStore
	            CredentialValidationResult result = identityStore.validate(new UsernamePasswordCredential(username, password));

	            if (result.getCallerPrincipal() != null && result.getCallerGroups() != null) {
	                return context.notifyContainerAboutLogin(result.getCallerPrincipal().getName(), result.getCallerGroups());
	            } else {
	                return AuthenticationStatus.SEND_FAILURE; // Maneja el error adecuadamente
	            }
//	            if (result.getStatus() == CredentialValidationResult.Status.VALID) {
//	                return context.notifyContainerAboutLogin(result.getCallerPrincipal(), result.getCallerGroups().stream().toList());
//	            }
	        }

	        // Si no hay credenciales o son inválidas, solicita autenticación
	        response.setHeader("WWW-Authenticate", "Basic realm=\"myRealm\"");
	        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	        return AuthenticationStatus.SEND_FAILURE;
	        
	    }
    //@Inject
    //private IdentityStoreHandler identityStoreHandler;

//	@Override
//    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
//
//        String name = request.getParameter("name");
//        String password = request.getParameter("password");
//
//        if (notNull(name, password)) {
//            return httpMessageContext.notifyContainerAboutLogin(
//                validate(
//                    new UsernamePasswordCredential(name, password)));
//
//        }
//
//        return httpMessageContext.doNothing();
//    }
//
//    public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {
//    	if (usernamePasswordCredential.compareTo("u1", "p1")) {
//        	Set<String> roles = new HashSet<>();
//        	roles.add("g1");
//        	roles.add("myRole");
//            return new CredentialValidationResult("u1", roles);
//        }
//    
//
//        return INVALID_RESULT;
//    }
//
//    public static boolean notNull(Object... objects) {
//		for (Object object : objects) {
//			if (object == null) {
//				return false;
//			}
//		}
//
//		return true;
//	}
//    
////    @Override
////    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
////
////    	// Get the (caller) name and password from the request
////        // NOTE: This is for the smallest possible example only. In practice
////        // putting the password in a request query parameter is highly
////        // insecure
////    	final String name = request.getParameter("name");
////        final String pwd = request.getParameter("password");
////
////        if (name != null && pwd != null ) {
////
////            // Get the (caller) name and password from the request
////            // NOTE: This is for the smallest possible example only. In practice
////            // putting the password in a request query parameter is highly
////            // insecure
////
////            Password password = new Password(pwd);
////
////            // Delegate the {credentials in -> identity data out} function to
////            // the Identity Store
////            CredentialValidationResult result = identityStoreHandler.validate(
////                    new UsernamePasswordCredential(name, password));
////
////            if (result.getStatus() == VALID) {
////                // Communicate the details of the authenticated user to the
////                // container. In many cases the underlying handler will just store the details 
////                // and the container will actually handle the login after we return from 
////                // this method.
////                return httpMessageContext.notifyContainerAboutLogin(
////                        result.getCallerPrincipal(), result.getCallerGroups());
////            }
////
////            return httpMessageContext.responseUnauthorized();
////        }
////
////        return httpMessageContext.doNothing();
////    }
    
}