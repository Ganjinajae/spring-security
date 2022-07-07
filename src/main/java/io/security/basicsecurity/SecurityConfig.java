package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .anyRequest().authenticated();
    http
        .formLogin();
    http
        .rememberMe();
    http
        .sessionManagement()
        .maximumSessions(1)
        .maxSessionsPreventsLogin(false)
        ;
    return http.build();
  }
}
