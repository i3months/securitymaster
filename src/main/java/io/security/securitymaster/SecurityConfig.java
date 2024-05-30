package io.security.securitymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { 

        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("customPram=y");
        
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .requestCache(cache -> cache.requestCache(requestCache))
            
            
            .rememberMe((rememberMe) -> rememberMe
                .alwaysRemember(true)
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService())
                .rememberMeParameter(null)
                .rememberMeCookieName(null)
                .key("security")
            )
            .anonymous(anonymous -> anonymous
                .principal("guest")
                .authorities("ROLE_GUEST")
            )

            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                .logoutSuccessUrl("/login")
                .logoutSuccessHandler(null)
                .deleteCookies("JSESSIONID", "COOKIE_NAME..")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, 
                            org.springframework.security.core.Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                        SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
                        SecurityContextHolder.getContextHolderStrategy().clearContext();
                    }
                })
                .permitAll()
                
            );

    
            return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 =  User.withUsername("user")
            .password("{noop}1111")
            .roles("USER").build();

        UserDetails user2 =  User.withUsername("user")
            .password("{noop}1111")
            .roles("USER").build();

        

        return new InMemoryUserDetailsManager(user1, user2);
    }
}
