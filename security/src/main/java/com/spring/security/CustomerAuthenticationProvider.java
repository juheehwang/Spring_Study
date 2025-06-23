//package com.spring.security;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Component;
//
//@Component
//@RequiredArgsConstructor
//public class CustomerAuthenticationProvider implements AuthenticationProvider {
//
//    private final UserDetailsService userDetailsService;
//
//    @Override
//    public Authentication authenticate(Authentication authentication)
//        throws AuthenticationException {
//        String loginId = authentication.getName();
//        String password = (String) authentication.getCredentials();
//        // 아이디 검증
//        UserDetails user = userDetailsService.loadUserByUsername(loginId);
//        if(user == null) throw new UsernameNotFoundException("no user~");
//        // 비밀번호 검증
//
//        return new UsernamePasswordAuthenticationToken(
//            user.getUsername(),
//            user.getPassword(),
//            user.getAuthorities()
//        );
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return false;
//    }
//}
