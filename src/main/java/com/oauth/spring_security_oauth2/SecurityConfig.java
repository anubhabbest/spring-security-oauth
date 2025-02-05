package com.oauth.spring_security_oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config .Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .oauth2Login(Customizer.withDefaults());
//
//        return http.build();
//    }
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/").authenticated()
                    .anyRequest().permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                    .successHandler((request, response, authentication) -> {
                        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
                        OAuth2AuthorizedClient client = getAuthorizedClient(authToken);
                        if (client != null) {
                            System.out.println("JWT Token: " + client.getAccessToken().getTokenValue());
//                            DecodedJWT jwt = JWT.decode(client.getAccessToken().getTokenValue());
//                            System.out.println( "Subject: " + jwt.getSubject() + "\nIssuer: " + jwt.getIssuer() + "\nClaims: " + jwt.getClaims());
                        }
                        response.sendRedirect("/"); // Redirect to homepage after login
                    })
            );

    return http.build();
}

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authToken) {
        return authorizedClientService.loadAuthorizedClient(
                authToken.getAuthorizedClientRegistrationId(),
                authToken.getName()
        );
    }

}
