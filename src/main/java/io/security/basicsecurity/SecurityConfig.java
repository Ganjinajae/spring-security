package io.security.basicsecurity;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

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
        .logout()
        .logoutUrl("/logout")
        .logoutSuccessUrl("/loginPage")
        .addLogoutHandler(new LogoutHandler() {
          @Override
          public void logout(HttpServletRequest request, HttpServletResponse response,
              Authentication authentication) {
            HttpSession session = request.getSession();
            session.invalidate();
          }
        })
        .logoutSuccessHandler(new LogoutSuccessHandler() {
          @Override
          public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
              Authentication authentication) throws IOException, ServletException {
            response.sendRedirect("/login");
          }
        })
          .deleteCookies("remember-me")
        .and()
        .rememberMe()
        .rememberMeParameter("remember")
        .tokenValiditySeconds(3600)
    ;
    return http.build();
  }
}
