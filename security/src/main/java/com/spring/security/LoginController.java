package com.spring.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final HttpSessionSecurityContextRepository sessionSecurityContextRepository= new HttpSessionSecurityContextRepository();

    @PostMapping("/login")
    public Authentication login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response){
        UsernamePasswordAuthenticationToken token =
            UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getUsername(),loginRequest.getPassword());
        Authentication authenticate = authenticationManager.authenticate(token);
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy()
            .createEmptyContext();
        securityContext.setAuthentication(authenticate);

        SecurityContextHolder.getContextHolderStrategy().setContext(securityContext); // threadlocal에 저장

        sessionSecurityContextRepository.saveContext(securityContext,request,response);
        return authenticate;

    }



}
