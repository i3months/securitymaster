package io.security.securitymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { 
        
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = builder.build();

        http.authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/user").hasAuthority("USER")
            .requestMatchers("/mypage/**").hasAuthority("USER")
            .requestMatchers(HttpMethod.GET, "/**").hasAuthority("read")
            .requestMatchers(RegexRequestMatcher.regexMatcher("/resource/[A-Z]")).hasAuthority("USER")
            .anyRequest().authenticated()
        );

        http.sessionManagement(session -> session
            .sessionFixation(sessionFixation -> sessionFixation.changeSessionId())
            .invalidSessionUrl("/invalid")
            .maximumSessions(1)
            .maxSessionsPreventsLogin(true)
            .expiredUrl("/expired")            
        );

        http.exceptionHandling(exception -> exception
            .authenticationEntryPoint((request, response, authException) -> {
                // ..
            })
            .accessDeniedHandler((request, response, accessDeniedException) -> {
                //...
            })
            
        );

            


        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .securityContext(securityContext -> securityContext.requireExplicitSave(false))
            .authenticationManager(authenticationManager);

    
            return http.build();
    }

    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter();
        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return customAuthenticationFilter;
        
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }

    // 하나만 사용할 시 자동 적용 
    // @Bean
    // public UserDetailsService userDetailsService() {
    //     UserDetails user1 =  User.withUsername("user")
    //         .password("{noop}1111")
    //         .roles("USER").build();

    //     UserDetails user2 =  User.withUsername("user")
    //         .password("{noop}1111")
    //         .roles("USER").build();

        

    //     return new InMemoryUserDetailsManager(user1, user2);
    // }
}
