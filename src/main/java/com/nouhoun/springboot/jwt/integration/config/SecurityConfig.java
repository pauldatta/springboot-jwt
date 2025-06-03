package com.nouhoun.springboot.jwt.integration.config;

import com.nimbusds.jose.jwk.JWKSet; // Added
import com.nimbusds.jose.jwk.RSAKey; // Added
import com.nimbusds.jose.jwk.source.JWKSource; // Added
import com.nimbusds.jose.proc.SecurityContext; // Added
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType; // Added
import org.springframework.security.oauth2.core.ClientAuthenticationMethod; // Added
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository; // Added
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient; // Added
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository; // Added
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings; // Added
import com.nouhoun.springboot.jwt.integration.service.impl.AppUserDetailsService; // Added import
// Removed: import com.nouhoun.springboot.jwt.integration.repository.UserRepository; // No longer needed here
// import org.springframework.security.provisioning.InMemoryUserDetailsManager; // Not used if AppUserDetailsService is primary
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.KeyPair; // Added
import java.security.KeyPairGenerator; // Added
import java.security.interfaces.RSAPrivateKey; // Added
import java.security.interfaces.RSAPublicKey; // Added
import java.util.UUID; // Added

@Configuration
@EnableWebSecurity
// @EnableGlobalMethodSecurity(prePostEnabled = true) // Remains commented out for now
public class SecurityConfig {

	@Value("${security.signing-key}")
	private String signingKey;

	@Value("${security.security-realm}")
	private String securityRealm;

    // Values moved from AuthorizationServerConfig
    @Value("${security.jwt.client-id}")
    private String clientId;
    @Value("${security.jwt.client-secret}")
    private String clientSecret;
    @Value("${security.jwt.scope-read}")
    private String scopeRead;
    @Value("${security.jwt.scope-write}")
    private String scopeWrite;

    // @Value fields are now directly injected into registeredClientRepository method parameters

    // Removed explicit AppUserDetailsService bean, relying on @Component scan
    // @Bean
    // public UserDetailsService appUserDetailsService(UserRepository userRepository) {
    //     return new AppUserDetailsService(userRepository);
    // }

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider(AppUserDetailsService appUserDetailsService, BCryptPasswordEncoder passwordEncoder) { // Inject AppUserDetailsService directly
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(appUserDetailsService); // Spring will inject the @Component AppUserDetailsService
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}

	@Bean
	public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider) {
		return new ProviderManager(daoAuthenticationProvider);
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());
		return http.build();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
				.issuer("http://localhost:8080")
				.tokenEndpoint("/oauth/token")
				.build();
	}

    // Beans moved from AuthorizationServerConfig
    @Bean
    public RegisteredClientRepository registeredClientRepository(
            @Value("${security.jwt.client-id}") String clientId,
            @Value("${security.jwt.client-secret}") String clientSecret,
            @Value("${security.jwt.scope-read}") String scopeRead,
            @Value("${security.jwt.scope-write}") String scopeWrite,
            BCryptPasswordEncoder passwordEncoder) { // Inject passwordEncoder
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret)) // Encode the secret
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1/authorized")
                .scope(scopeRead)
                .scope(scopeWrite)
                .clientSettings(ClientSettings.builder().requireProofKey(false).requireAuthorizationConsent(false).build())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
    // End of beans moved from AuthorizationServerConfig


	// DefaultSecurityFilterChain remains commented out
	// @Bean
	// @Order(Ordered.LOWEST_PRECEDENCE)
	// public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception { //...}


	@Bean
	public JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
		String jwkSetUri = issuerUri + "/oauth2/jwks";
		return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
	}

	// The AppUserDetailsService bean is expected to be picked up by component scan
	// If not, the UserDetailsService bean below would be used (which was for "user", not "john.doe")
	// For now, relying on AppUserDetailsService @Component to be the primary UserDetailsService.
	// @Bean
	// public UserDetailsService userDetailsService() { // This was the generic "user"
	// 	UserDetails user = User.builder()
	// 			.username("user")
	// 			.password(passwordEncoder().encode("password"))
	// 			.roles("USER")
	// 			.build();
	// 	return new InMemoryUserDetailsManager(user);
	// }
}
