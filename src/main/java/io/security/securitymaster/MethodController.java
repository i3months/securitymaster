package io.security.securitymaster;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
public class MethodController {
    
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String test() {
        return "test";
    }

    @PostAuthorize("hasAuthority('ROLE_ADMIN') and returnObject.isSecure")
    public Account secureAccount(String name, String secure) {
        return new Account(name, "Y".equals(secure));
    }

    @PostMapping("/writelist")
    public List<Account> writeList(@RequestBody List<Account> data) {
        
        return dataService.();
        
    }
    
}