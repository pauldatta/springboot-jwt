package com.nouhoun.springboot.jwt.integration.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered; // Added this import
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ResourceServerConfig {

    // ResourceServerTokenServices and resourceIds from the old config are not directly mapped here.
    // JWT validation (which tokenServices implicitly handled via DefaultTokenServices in SecurityConfig)
    // will be configured via .oauth2ResourceServer().jwt() and properties like spring.security.oauth2.resourceserver.jwt.jwk-set-uri or issuer-uri.
    // Resource ID validation can be done via audience claim validation in JWTs.
    // This might require adjustments in how SecurityConfig or AuthorizationServerConfig provides JWT details.

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1) // Ensure this is processed after AuthorizationServerSecurityFilterChain
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .requestMatchers(matchers ->
                matchers
                    .antMatchers("/springjwt/**")
                    .antMatchers("/api/user/**")
            )
            .authorizeRequests(authorizeRequests ->
                authorizeRequests
                    // .antMatchers("/actuator/**", "/api-docs/**").permitAll() // These should be handled by a different filter chain or be part of a broader public path config
                    .antMatchers("/springjwt/**").authenticated()
                    .antMatchers("/api/user/**").authenticated() // Example of another resource path
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt()); // Configure as an OAuth2 resource server validating JWTs

        return http.build();
    }
}
