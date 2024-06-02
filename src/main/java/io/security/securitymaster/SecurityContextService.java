package io.security.securitymaster;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextService {

    public void securityContext() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        /**
         * 쓰레드로컬에서 바로 가져오지 않고 Supplier 를 통해 가져옴 
         */
    }
    
}
