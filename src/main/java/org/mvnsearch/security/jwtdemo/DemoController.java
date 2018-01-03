package org.mvnsearch.security.jwtdemo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * demo controller
 *
 * @author linux_china
 */
@RestController
public class DemoController {

    @GetMapping("/hello")
    @PreAuthorize("hasRole('USER')")
    public String hello(Principal userPrincipal) {
        return "hello " + userPrincipal.getName();
    }

    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
