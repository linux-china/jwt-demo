package org.mvnsearch.security.jwtdemo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.Test;

import java.util.Date;

/**
 * JWT test
 *
 * @author linux_china
 */
public class JwtTest {

    @Test
    public void testGenerateToken() throws Exception {
        Algorithm algorithmHS = Algorithm.HMAC256("secret");
        String token = JWT.create()
                .withIssuer("mvnsearch")
                .withAudience("Admin")
                .withSubject("jackie")
                .withIssuedAt(new Date())
                .sign(algorithmHS);
        System.out.println(token);
    }
}
