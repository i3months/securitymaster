package io.security.securitymaster;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { 
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin((form) -> form
                .loginPage("/login")
                .loginProcessingUrl("/loginProcess")
                .defaultSuccessUrl("/", true)
                .failureUrl("/failed")
                .usernameParameter("username")
                .passwordParameter("password")
                .failureHandler(null)
                .successHandler(null)
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
