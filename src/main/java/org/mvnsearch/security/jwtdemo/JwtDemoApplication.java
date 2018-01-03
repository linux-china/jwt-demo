package org.mvnsearch.security.jwtdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class JwtDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtDemoApplication.class, args);
	}
}
