package com.nouhoun.springboot.jwt.integration.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
// import org.springframework.context.annotation.Primary; // No longer needed as DefaultTokenServices is removed
import org.springframework.core.Ordered; // Added for @Order
import org.springframework.core.annotation.Order; // Added for @Order
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Created by nydiarra on 06/05/17.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

	@Value("${security.signing-key}")
	private String signingKey;

	// This was removed from application.properties, so removing the injection here.
	// @Value("${security.encoding-strength}")
	// private Integer encodingStrength;

	@Value("${security.security-realm}")
	private String securityRealm;

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(); // encodingStrength is not a direct param for BCrypt
	}

	// Temporarily removing this bean to see if it resolves the 404 on /oauth2/token
	// @Bean
	// @Order(Ordered.LOWEST_PRECEDENCE) // Explicitly set lower precedence
	// public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
	// 	http
	// 			.requestMatchers(matchers -> matchers.antMatchers("/general/**")) // Apply only to specific, non-conflicting paths
	// 			.authorizeRequests(authorizeRequests ->
	// 					authorizeRequests.anyRequest().authenticated()
	// 			)
	// 			.sessionManagement(sessionManagement ->
	// 					sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	// 			)
	// 			.httpBasic(httpBasic -> httpBasic.realmName(securityRealm))
	// 			.csrf(csrf -> csrf.disable());
	// 	return http.build();
	// }

	@Bean
	public JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
		// The Resource Server will validate tokens using the Authorization Server's JWK Set URI
		// This URI should match the issuer URI configured in AuthorizationServerSettings
		// Ensure the Authorization Server is configured to expose its JWK Set endpoint (default is /oauth2/jwks)
		String jwkSetUri = issuerUri + "/oauth2/jwks";
		return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.builder()
				.username("user")
				.password(passwordEncoder().encode("password")) // Ensure passwordEncoder bean is available
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}
}
