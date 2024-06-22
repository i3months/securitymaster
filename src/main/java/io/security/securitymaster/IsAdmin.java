package io.security.securitymaster;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.access.prepost.PostAuthorize;

@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({{TYPE, METHOD}})
@PostAuthorize("returnObject.owner == authentication.name")
public @interface IsAdmin {
    
}
