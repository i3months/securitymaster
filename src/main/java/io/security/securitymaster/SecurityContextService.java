package io.security.securitymaster;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {

    public void securityContext() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
    }
    
}
