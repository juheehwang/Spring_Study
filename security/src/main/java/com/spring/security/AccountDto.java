package com.spring.security;

import java.util.Collection;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@AllArgsConstructor
@Getter
public class AccountDto {

    private String username;
    private String password;
    private Collection<GrantedAuthority> authorities;

}
