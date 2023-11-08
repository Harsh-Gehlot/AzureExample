package com.example.azureExample;

import java.util.Collection;
import java.util.Collections;

import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsServiceImpl();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Use a proper password encoder in production
        return NoOpPasswordEncoder.getInstance();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
        http
            .authorizeHttpRequests(auth-> auth.anyRequest().authenticated())
            .oauth2Login(oauth2Login -> oauth2Login.clientRegistrationRepository(clientRegistrationRepository())
                ); //(Customizer.withDefaults());    
        // .and()
        // .oauth2Login(oauth2Login -> oauth2Login
        //         .authorizationEndpoint()
        //             .baseUri("/login/oauth2/code/")
        //         .and()
        //         .clientRegistration("azure-dev")
        //             .clientId("YOUR_CLIENT_ID")
        //             .clientSecret("YOUR_CLIENT_SECRET")
        //             .authorizationUri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
        //             .tokenUri("https://login.microsoftonline.com/common/oauth2/v2.0/token")
        //             .scope("openid", "profile", "email")
        //         .and()
        //         .redirectionUri("http://localhost:8080/oauth2/login/azure-dev")
        // )
        // .and()
        // .exceptionHandling()
        //     .authenticationEntryPoint(unauthorizedEntryPoint())
        //     .accessDeniedHandler(accessDeniedHandler());

            return http.build();
        }

    //     @Bean
    //     public UnauthorizedEntryPoint unauthorizedEntryPoint() {
    //         return new HttpStatusUnauthorizedEntryPoint();
    //     }

    //     @Bean
    //     public AccessDeniedHandler accessDeniedHandler() {
    //         return new HttpStatusForbiddenEntryPoint();
    //     }
        @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return registrationId -> {
                // Define your custom ClientRegistration details here
                if ("azure-dev".equals(registrationId)) {
                    return customAzureADClientRegistration();
                }
                return null;
            };
        }

        private ClientRegistration customAzureADClientRegistration() {
            // Define and configure your custom Azure AD client registration
            return ClientRegistration
                    .withRegistrationId("azure-dev")
                    .clientId("8d6ba799-97bc-44fd-b0ea-101151004e6c")
                    .clientSecret("2Q_8Q~yyYri7x9nVyDTdtPjwWNPIdSsMcXxI~b9H")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationUri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
                    .tokenUri("https://login.microsoftonline.com/common/oauth2/v2.0/token")
                    .userInfoUri("https://graph.microsoft.com/v1.0/me")
                    .scope("openid", "profile", "email")
                    .redirectUri("http://localhost:8080/login/oauth2/code/")
                    .build();
        }

        // @Bean
        // public UserDetailsService customUserDetailsService() {
        //     // Define your custom user details service
        //     return new CustomUserDetailsServiceImpl();
        // }
        public class CustomUserDetailsServiceImpl implements UserDetailsService {

            // Replace this with your actual user data retrieval logic
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                if ("HARSHGEHLOT@sar24singmail.onmicrosoft.com".equals(username)) {
                    CustomUserDetails user = new CustomUserDetails();
                    user.setUsername("HARSHGEHLOT@sar24singmail.onmicrosoft.com");
                    user.setPassword("Muvo832465Muvo832465"); // Replace with actual password
                    // Define user's roles/authorities
                    user.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
                    return user;
                } else {
                    throw new UsernameNotFoundException("User not found with username: " + username);
                }
            }
        }
}

class CustomUserDetails implements UserDetails {
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(){}
    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities){
        this.username = username;
        this.password = password;
    }

    public String getusername(){
        return this.username;
    }
    public String getpassword(){
        return this.password;
    }
    public void setUsername(String username){
         this.username = username;
    }
    public void setPassword(String password){
        this.password = password;
   }
   public void setAuthorities(Collection<? extends GrantedAuthority> authorities){
    this.authorities = authorities;
}
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
