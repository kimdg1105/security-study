package org.example.securitystudy.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder auth =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication()
                .withUser("admin").password("{noop}1234").roles("ADMIN");

        return auth.build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests.requestMatchers("/user").hasRole("USER")
                                .requestMatchers("/login").permitAll()
                                .requestMatchers("/admin").hasRole("ADMIN")
                                .requestMatchers("/admin/pay").hasRole("ADMIN")
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                                .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                        .defaultSuccessUrl("/")
                        .successHandler((request, response, authentication) -> {
                            RequestCache requestCache = new HttpSessionRequestCache();
                            SavedRequest savedRequest = requestCache.getRequest(request, response);
                            response.sendRedirect(savedRequest.getRedirectUrl());

                            log.info("authentication: {}", authentication.getName());
                        })
                        .permitAll()
                );
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    log.info("accessDeniedException: {}", accessDeniedException.getMessage());
                    response.sendRedirect("/denied");
                })
                .authenticationEntryPoint((request, response, authException) -> {
                    log.info("authException: {}", authException.getMessage());
                    response.sendRedirect("/login");
                })
        );

        http.sessionManagement(sessionManagement -> sessionManagement
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::none)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .expiredUrl("/login")
        );

        return http.build();
    }

}
