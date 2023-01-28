package io.security.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

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
            .antMatchers("/user").hasRole("USER")
            .antMatchers("/admin/pay").hasRole("ADMIN") // 구체적인 범위가 위에 와있어야함, 아래와 순서 바뀌면 sys권한으로 admin/pay 접근 가능함
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated();

    return http.build();
  }
}
