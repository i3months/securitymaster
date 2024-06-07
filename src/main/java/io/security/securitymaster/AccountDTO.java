package io.security.securitymaster;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import lombok.Getter;

@Getter
public class AccountDTO {
    private String username;
    private String password;
    private Collection<GrantedAuthority> authorities;
    
}
