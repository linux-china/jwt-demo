package org.mvnsearch.security.jwtdemo;

import org.mvnsearch.security.jwtdemo.jwt.JWTAuthenticationFilter;
import org.mvnsearch.security.jwtdemo.jwt.JwtAuthenticationProvider;
import org.mvnsearch.security.jwtdemo.jwt.JwtUserDetailService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * jwt security configurer adapter
 *
 * @author linux_china
 */
@Configuration
@EnableWebSecurity
public class JwtSecurityConfigurerAdapter extends WebSecurityConfiguration {
  /**
   * white urls for static resources
   */
  @Value("${security.ignored}")
  public String[] whiteUrls;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.addFilterAfter(new JWTAuthenticationFilter(), SecurityContextHolderFilter.class)
      .securityMatcher(whiteUrls).authorizeHttpRequests(registry -> registry.anyRequest().permitAll())
      .authorizeHttpRequests((authz) -> authz
        .anyRequest().authenticated()
      )
      .sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .csrf(AbstractHttpConfigurer::disable)
      .exceptionHandling(configurer -> {
        configurer.authenticationEntryPoint((request, response, authException) -> {
          response.sendError(401, "Access Denied: please add legal JWT token on Authorization(HTTP header). Detail: " + authException.getMessage() + " If you have problem, please contact linux_china");
        });
        configurer.accessDeniedHandler((request, response, accessDeniedException) -> {
        });
      }).build();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return (webSecurity) -> webSecurity.ignoring().requestMatchers(whiteUrls);
  }

  @Bean
  public AuthenticationProvider jwtAuthenticationProvider(UserDetailsService userDetailsService) throws Exception {
    return new JwtAuthenticationProvider(userDetailsService);
  }

  @Bean
  public UserDetailsService jwtUserDetailsService() {
    return new JwtUserDetailService();
  }

}
