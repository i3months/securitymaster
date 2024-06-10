package io.security.securitymaster;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component("customWebSecurity")
public class CustomWebSecurity {
    
    public boolean check(Authentication authentication, HttpServletRequest request) {
        return authentication.isAuthenticated(); // 권한 관련 로직 설정 가능 
    }
}
