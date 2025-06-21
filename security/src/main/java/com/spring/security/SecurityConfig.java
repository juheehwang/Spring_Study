package com.spring.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//            .formLogin(Customizer.withDefaults())
//            .rememberMe(rememberMe -> rememberMe
//               // .alwaysRemember(true)
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService())
//                .rememberMeParameter("remember")
//                .rememberMeCookieName("remember")
//                .key("security")
//            );

        // logout test
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//            .formLogin(Customizer.withDefaults())
//            .logout(logout -> logout
//                .logoutUrl("/logoutProc")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "POST")) // 이게 logoutUrl 보다 우선됨 - post를 명시안하면 어떤 method 든 가능
//                .logoutSuccessUrl("/logoutSuccess") //이게 동작하려면 requestMatchers() 에 등록해야함
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request,
//                        HttpServletResponse response, Authentication authentication)
//                        throws IOException, ServletException {
//                        response.sendRedirect("/logoutSuccess");
//                    }
//                }) //이게 logoutSuccessUrl 보다 우선 실행된다
//                .deleteCookies("JSESSIONID")
//                .invalidateHttpSession(true)
//                .clearAuthentication(true)
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response,
//                        Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                        SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
//                        SecurityContextHolder.getContextHolderStrategy().clearContext();
//                    }
//                })
//                .permitAll()
//            );

        // 기본
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/login").permitAll()
            .anyRequest().authenticated())
     //       .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
        throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user = User.withUsername("user")
            .password("{noop}1111")
            .roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
