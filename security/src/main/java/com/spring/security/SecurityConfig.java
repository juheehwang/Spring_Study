package com.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // formLogin() API version
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//            .formLogin(form -> form
//                .loginPage("/loginPage")
//                .loginProcessingUrl("/loginProc")
//                .defaultSuccessUrl("/",true)
//                .failureUrl("/failed")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .successHandler((request, response, authentication) -> {
//                    System.out.println("authentication : " + authentication);
//                    response.sendRedirect("/home");
//                })
//                .failureHandler((request, response, exception) -> {
//                    System.out.println("exception : "+ exception.getMessage());
//                    response.sendRedirect("/login");
//                })
//                .permitAll()
//            );
        // http basic version
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//            .httpBasic(basic -> basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));

        // remember me test
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .rememberMe(rememberMe -> rememberMe
               // .alwaysRemember(true)
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService())
                .rememberMeParameter("remember")
                .rememberMeCookieName("remember")
                .key("security")
            );


        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("user")
            .password("{noop}1111")
            .roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
