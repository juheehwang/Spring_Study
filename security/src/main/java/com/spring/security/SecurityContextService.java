package com.spring.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {

    public void securityContext(){
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication auth = context.getAuthentication();
        System.out.println("auth === "+auth);
    }

}
