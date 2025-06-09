package com.spring.security;

import java.util.Collection;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

@Getter
@AllArgsConstructor
public class AccountDto {

    private String username;
    private String password;
    private Collection<GrantedAuthority> authorities;

}
