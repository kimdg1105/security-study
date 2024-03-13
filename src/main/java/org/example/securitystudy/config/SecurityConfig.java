package org.example.securitystudy.config;

import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.anyRequest().authenticated())
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/")
                        .failureUrl("/login")
                        .loginProcessingUrl("/login_proc")
                        .successHandler((request, response, authentication) -> {
                            log.info("authentication: {}", authentication.getName());
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> {
                            log.info("exception: {}", exception.getMessage());
                            response.sendRedirect("/login");
                        })
                        .permitAll()
                );

        http.logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> {
                    log.info("Logout Success. authentication: {}", authentication.getName());
                    response.sendRedirect("/login");
                })
                .deleteCookies("remember-me")
                .permitAll()
        );

        http.rememberMe(rememberMe -> rememberMe
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(3600)
        );
        return http.build();
    }

}
