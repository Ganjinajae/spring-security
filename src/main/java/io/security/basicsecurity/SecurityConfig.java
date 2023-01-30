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
                .antMatcher("/admin/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic(); // 인증 방식

        return http.build();
    }
}

@Configuration
class SecurityConfig2 {

    @Bean
    protected SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin();

        return http.build();
    }
}
