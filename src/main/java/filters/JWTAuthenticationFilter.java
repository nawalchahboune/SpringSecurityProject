package filters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.sid.AppRole;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JWTAuthenticationFilter  extends UsernamePasswordAuthenticationFilter {
    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    //quand l'utilisateur tente de s'authentifier
    //Authentication object contient les infos sur l'utilisateur
    //apres c'est springSecurityFilter qui prend le relai
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        System.out.println("attempting to authenticate user: " + username);
        System.out.println(username);
        System.out.println(password);

        UsernamePasswordAuthenticationToken tokenUse=new UsernamePasswordAuthenticationToken(username, password);
        return this.authenticationManager.authenticate(tokenUse);
    }
    // deuxieme méthode renvoie authorization
    //elle est appelée quant l'authentication est réussie


    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            javax.servlet.FilterChain chain, Authentication authResult)
            throws java.io.IOException, javax.servlet.ServletException {
        System.out.println("authentication successful");
        System.out.println("generate JWT token");
        User user = (User) authResult.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("ma clé :)");
        String JWTAccessToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 5*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles",user.getAuthorities().stream().map(r->r.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm);

        response.addHeader( "Authorization", "Bearer " +JWTAccessToken);
        String JWTRefreshToken = JWT.create()
                                   .withSubject(user.getUsername())
                                   .withExpiresAt(new Date(System.currentTimeMillis() + 15*60*1000))
                                   .withIssuer(request.getRequestURL().toString())
                                   .sign(algorithm);
        Map<String ,String > idTokens= new HashMap<>();
        idTokens.put("AccessToken", JWTAccessToken);
        idTokens.put("RefreshToken", JWTRefreshToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getWriter(),idTokens);


    }





}
