package com.onndoo.security.config;

import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static jakarta.security.enterprise.identitystore.CredentialValidationResult.INVALID_RESULT;
import static jakarta.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;
import static jakarta.security.enterprise.identitystore.IdentityStore.ValidationType.VALIDATE;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.security.enterprise.credential.Credential;
import jakarta.security.enterprise.credential.UsernamePasswordCredential;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;

@ApplicationScoped
public class MyIdentityStore implements IdentityStore {
	
	
	    @Override
	    public CredentialValidationResult validate(Credential credential) {
	        // Verifica si las credenciales son de tipo UsernamePasswordCredential
	        if (credential instanceof UsernamePasswordCredential) {
	            UsernamePasswordCredential upCredential = (UsernamePasswordCredential) credential;

	            // Valida el usuario y la contraseña
	            if (isValidUser(upCredential.getCaller(), upCredential.getPassword())) {
	                // Si es válido, devuelve un resultado positivo
	            	Set<String> roles = new HashSet<>();
	              roles.add("g1");
	              roles.add("g2");
	              roles.add("foo");
	              
	                return new CredentialValidationResult(upCredential.getCaller(), Set.of("foo","g1"));
	            }
	        }
	        // Si las credenciales no son válidas, devuelve un resultado inválido
	        return CredentialValidationResult.INVALID_RESULT;
	    }

	    private boolean isValidUser(String username, jakarta.security.enterprise.credential.Password inputPassword) {
	        // Recuperar la contraseña almacenada para el usuario desde una base de datos u otra fuente
	        String storedPassword = getStoredPasswordForUser(username);

	        // Compara la contraseña proporcionada con la almacenada
	        return inputPassword.compareTo(storedPassword);
	    }
	    
	    private String getStoredPasswordForUser(String username) {
	        // Simula la recuperación de la contraseña desde una base de datos
	        // En un caso real, conectarías con tu base de datos y buscarías el registro del usuario
	        if ("admin".equals(username)) {
	            return "1234"; // Ejemplo estático, no usar en producción
	        }
	        
	        if ("emma".equals(username)) {
	            return "secret2"; // Ejemplo estático, no usar en producción
	        }
	        return null; // Usuario no encontrado
	    }
	    	    
	    @Override
	    public int priority() {
	        return 1000;
	    }

	    @Override
	    public Set<ValidationType> validationTypes() {
	        return unmodifiableSet(VALIDATE);
	    }
	    
	    public static <E> Set<E> unmodifiableSet(Object... values) {
			Set<E> set = new HashSet<>();

			for (Object value : values) {
				if (value instanceof Object[]) {
					for (Object item : (Object[]) value) {
						set.add((E) item);
					}
				}
				else if (value instanceof Collection<?>) {
					for (Object item : (Collection<?>) value) {
						set.add((E) item);
					}
				}
				else {
					set.add((E) value);
				}
			}

			return Collections.unmodifiableSet(set);
		}
}
	/*
	public CredentialValidationResult validate(UsernamePasswordCredential usernamePasswordCredential) {

        if (usernamePasswordCredential.compareTo("u1", "p1")) {
        	Set<String> roles = new HashSet<>();
        	roles.add("g1");
        	roles.add("myRole");
            return new CredentialValidationResult("u1", roles);
        }

        return INVALID_RESULT;
    }
	
	
//	@Override
//    public CredentialValidationResult validate(Credential credential) {
//		
//		CredentialValidationResult result = NOT_VALIDATED_RESULT;
//		
//		if (credential instanceof UsernamePasswordCredential) {
//            UsernamePasswordCredential usernamePassword = (UsernamePasswordCredential) credential;
//
//            if (usernamePassword.compareTo("u1", "p1")) {
//              Set<String> roles = new HashSet<>();
//              roles.add("g1");
//              return new CredentialValidationResult("u1", roles);
//          }
//            if ("rudy".equals(usernamePassword.getCaller())) {
//
//                result = INVALID_RESULT;
//            }
//        }
//        return result;
        
//    	if (usernamePasswordCredential == null) {
//            throw new IllegalArgumentException("usernamePasswordCredential cannot be null");
//        }
//        if (usernamePasswordCredential.compareTo("u1", "p1")) {
//            Set<String> roles = new HashSet<>();
//            roles.add("g1");
//            return new CredentialValidationResult("u1", roles);
//        }
//        return CredentialValidationResult.INVALID_RESULT;
    //}
	
	 
	    
}*/
