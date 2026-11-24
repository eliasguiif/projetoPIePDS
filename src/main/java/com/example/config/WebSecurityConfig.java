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

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;

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
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> suapUserService() {

        DefaultOAuth2UserService service = new DefaultOAuth2UserService();

        return userRequest -> {

            OAuth2User usuario = service.loadUser(userRequest);

            String tipoUsuario = usuario.getAttribute("tipo_usuario");

            Set<GrantedAuthority> permissoes =
                    new HashSet<>(usuario.getAuthorities());

            if ("Aluno".equalsIgnoreCase(tipoUsuario)) {

                permissoes.add(
                        new SimpleGrantedAuthority("ROLE_ALUNO")
                );

            } else if ("Servidor".equalsIgnoreCase(tipoUsuario)) { //----substituir pelo tipo de user

                // Regra provisoria, somente para testes
                permissoes.add(
                        new SimpleGrantedAuthority("ROLE_PROFESSOR")
                );

            }

            System.out.println("Tipo de usuario: " + tipoUsuario);
            System.out.println("Permissoes: " + permissoes);

            return new DefaultOAuth2User(
                    permissoes,
                    usuario.getAttributes(),
                    "identificacao"
            );
        };
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
