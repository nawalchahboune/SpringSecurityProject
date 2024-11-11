package secSecurityApplication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

import filters.JWTAuthenticationFilter;
import filters.JWTAuthorizationFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.sid.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import service.Service1;

import static org.springframework.security.config.http.MatcherType.mvc;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityConfig {
    private   AuthenticationManager AuthenticationManager;
    @Autowired
    private Service1 accountService;
    @Autowired private HttpServletRequest httpServletRequest;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HttpSession httpSession) throws Exception {


        System.out.println("cc");
        http.csrf(AbstractHttpConfigurer::disable
        )

         .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.disable()) // Permet les iframes pour H2
        );
       // http.formLogin(formLogin ->
         //       formLogin
           //             .loginPage("/login")
        //);
        http.authorizeHttpRequests(authz -> {
                    authz
                            .requestMatchers(antMatcher("/login/**")).permitAll()
                            .anyRequest().authenticated();
                }
        );
        System.out.println("why ?");

        http.addFilter(new JWTAuthenticationFilter(AuthenticationManager));
        http.addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    public void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser user= accountService.loadUserByUsername(username);

                Collection<GrantedAuthority> authorities= new ArrayList<>();

                user.getRoles().forEach(r->{
                    authorities.add(new SimpleGrantedAuthority(r.getDescription()));
                });

                return new User(user.getUsername(),user.getPassword(),authorities);

            }

        });
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }



}
