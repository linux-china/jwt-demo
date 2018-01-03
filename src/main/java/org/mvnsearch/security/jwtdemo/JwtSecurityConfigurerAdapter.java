package org.mvnsearch.security.jwtdemo;

import org.mvnsearch.security.jwtdemo.jwt.JWTAuthenticationFilter;
import org.mvnsearch.security.jwtdemo.jwt.JwtAuthenticationProvider;
import org.mvnsearch.security.jwtdemo.jwt.JwtUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * jwt security configurer adapter
 *
 * @author linux_china
 */
@Configuration
@EnableWebSecurity
public class JwtSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    /**
     * white urls for static resources
     */
    @Value("${security.ignored}")
    public String[] whiteUrls;

    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(new JWTAuthenticationFilter(), SecurityContextPersistenceFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(whiteUrls).permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
                .httpBasic().disable()
                .exceptionHandling().accessDeniedPage("/403");
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth, AuthenticationProvider authenticationProvider, UserDetailsService userDetailsService) throws Exception {
        auth.authenticationProvider(authenticationProvider).userDetailsService(userDetailsService);
    }

    @Bean
    public AuthenticationProvider jwtAuthenticationProvider(UserDetailsService userDetailsService) throws Exception {
        return new JwtAuthenticationProvider(userDetailsService);
    }

    @Bean
    public UserDetailsService jwtUserDetailsService() {
        return new JwtUserDetailService();
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
