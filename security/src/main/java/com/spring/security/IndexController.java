package com.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @Autowired
    SecurityContextService securityContextService;

    @GetMapping("/")
    public String index(){
        SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication auth = context.getAuthentication();
        System.out.println("auth === "+auth);

        securityContextService.securityContext();

        return "index";
    }

    @GetMapping("/loginPage")
    public String loginPage(){
        return "<h1> loginPage </h1>";
    }

    @GetMapping("/home")
    public String home(){
        return "home~~~";
    }

    @GetMapping("/logoutSuccess")
    public String logoutSuccess(){
        return "logoutSuccess~~~!!";
    }
}
