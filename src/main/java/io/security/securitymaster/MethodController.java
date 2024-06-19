package io.security.securitymaster;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MethodController {
    
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String test() {
        return "test";
    }

    @PostAuthorize("hasAuthority('ROLE_ADMIN') and returnObject.isSecure")
    public Account secureAccount(String name, String secure) {
        return new Account(name, "Y".equals(secure));
    }
}
