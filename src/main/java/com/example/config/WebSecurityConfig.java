package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepository
    ) throws Exception {

        http.authorizeHttpRequests(autorize -> autorize
                .requestMatchers("/", "/login", "/oauth2/**", "/login/oauth2/**").permitAll()
                .requestMatchers("/usuarios/**", "/administrativo/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        )
        .formLogin(formLogin -> formLogin
                .loginPage("/login")
                .permitAll()
        )
        
        .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
                .authorizationEndpoint(endpoint -> endpoint
                        .authorizationRequestResolver(
                                authorizationRequestResolver(clientRegistrationRepository)
                        )
                )
                .userInfoEndpoint(userInfo -> userInfo
                        .userService(suapUserService())
                )
                .failureHandler((request, response, exception) -> {
                    exception.printStackTrace();
                    response.sendRedirect("/login?error");
                })
        )
        
        
        .logout(logout -> logout.permitAll());

        return http.build();
    }
    @Bean
    public DefaultOAuth2UserService suapUserService() {

        DefaultOAuth2UserService service = new DefaultOAuth2UserService();

        service.setAttributesConverter(userRequest -> attributes -> {

            System.out.println("===== ATRIBUTOS DO SUAP =====");

            attributes.forEach((chave, valor) -> {
                System.out.println(chave);

                if (valor instanceof java.util.Map<?, ?> mapa) {
                    System.out.println("Campos internos: " + mapa.keySet());
                }
            });

            System.out.println("============================");

            System.out.println("Tipo de usuario: " + attributes.get("tipo_usuario"));
            
            return attributes;
        });

        return service;
    }
    
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository repository) {

        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        repository,
                        "/oauth2/authorization"
                );

        resolver.setAuthorizationRequestCustomizer(builder ->
                builder.additionalParameters(params ->
                        params.put("prompt", "login")
                )
        );

        return resolver;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
