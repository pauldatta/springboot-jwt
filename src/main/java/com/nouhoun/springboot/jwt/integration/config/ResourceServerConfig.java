package com.nouhoun.springboot.jwt.integration.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            // .requestMatchers() // This was in the original, but its necessity depends on whether this is the ONLY HttpSecurity config.
            // If SecurityConfig also defines a SecurityFilterChain, then requestMatchers might be needed to scope this one.
            // For now, let's assume this will be the primary chain for resource server paths or that SecurityConfig will be adapted.
            .authorizeRequests(authorizeRequests ->
                authorizeRequests
                    .antMatchers("/actuator/**", "/api-docs/**").permitAll()
                    .antMatchers("/springjwt/**").authenticated() // Preserving the original scope
                    .anyRequest().authenticated() // Ensuring any other request is also authenticated if not covered
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt()); // Configure as an OAuth2 resource server validating JWTs

        return http.build();
    }
}
