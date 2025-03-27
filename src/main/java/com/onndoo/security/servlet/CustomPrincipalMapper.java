package com.onndoo.security.servlet;

import java.util.Set;

import javax.security.auth.Subject;

import org.glassfish.exousia.spi.PrincipalMapper;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
public class CustomPrincipalMapper implements PrincipalMapper {

	@Override
	public List<String> getMappedRoles(Iterable<Principal> principals, Subject subject) {
List<String> roles = new ArrayList();
        
        // Itera sobre los Principals (usuarios)
        for (Principal principal : principals) {
            String principalName = principal.getName();
            
            // Agregar roles basados en el nombre del Principal (usuario)
            if (principalName.equals("admin")) {
                roles.add("ROLE_ADMIN");
            } else if (principalName.equals("user")) {
                roles.add("ROLE_USER");
            } else {
                roles.add("ROLE_GUEST");
            }
        }
        
        return roles;
	}
}
