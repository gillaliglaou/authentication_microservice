package com.Collary.Authentification.system.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    // Constructor to inject JwtAuthConverter and CustomAuthenticationSuccessHandler
    public SecurityConfig(JwtAuthConverter jwtAuthConverter, CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler) {
        this.jwtAuthConverter = jwtAuthConverter;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
    }

    // Bean for RestTemplate to make REST calls within the application
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    // Bean to manage OAuth2 clients: refresh of tokens
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        // Configure the OAuth2 client to support token refresh
        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken() // Enables refresh token support
                .build();

        // Create and configure the authorized client manager
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    // Security filter chain to define how HTTP requests are secured in the application
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for simplicity, as this is an API-based application
                .csrf().disable()

                // Define authorization rules for different endpoints
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/demo/admin_access").hasRole("manager_admin")
                        .requestMatchers("/api/v1/demo/**").hasRole("client_employé")
                        .anyRequest().authenticated()
                )

                // Configure the session management to be stateless since we're using JWT
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configure OAuth2 resource server to use JWT tokens with a custom converter
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
                )

                // Handle OAuth2 login success by redirecting users based on their roles
                .oauth2Login(oauth2Login -> oauth2Login
                        .successHandler(customAuthenticationSuccessHandler)
                );

        return http.build();
    }
}
