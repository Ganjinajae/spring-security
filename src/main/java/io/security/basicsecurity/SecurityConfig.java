package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public UserDetailsManager users() {
    UserDetails user = User.builder()
            .username("user")
            .password("{noop}1111")
            .roles("USER")
            .build();
    UserDetails sys = User.builder()
            .username("user")
            .password("{noop}1111")
            .roles("SYS", "USER")
            .build();
    UserDetails admin = User.builder()
            .username("user")
            .password("{noop}1111")
            .roles("ADMIN", "SYS", "USER") // role hierarchy 기능 통하면 이렇게 안 해도 됨
            .build();
    return new InMemoryUserDetailsManager(user, sys, admin);
  }

  @Bean
  protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .antMatchers("/login").permitAll()
            .antMatchers("/user").hasRole("USER")
            .antMatchers("/admin/pay").hasRole("ADMIN") // 구체적인 범위가 위에 와있어야함, 아래와 순서 바뀌면 sys권한으로 admin/pay 접근 가능함
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated();
    http
            .formLogin()
            .successHandler((request, response, authentication) -> {
              RequestCache requestCache = new HttpSessionRequestCache();
              SavedRequest savedRequest = requestCache.getRequest(request, response);
              String redirectUrl = savedRequest.getRedirectUrl();
              response.sendRedirect(redirectUrl);
            });
    http
            .exceptionHandling()
            .authenticationEntryPoint((request, response, authException) -> response.sendRedirect("/login"))
            .accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/denied"));

    return http.build();
  }
}
