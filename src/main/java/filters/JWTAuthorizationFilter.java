package filters;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.filters.ExpiresFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if ((authorizationHeader != null) && authorizationHeader.startsWith("Bearer ")) {
           try{
               String Accestoken = authorizationHeader.substring(7);
               Algorithm algorithm = Algorithm.HMAC256("ma clé :)");
               JWTVerifier jwtVerifier= JWT.require(algorithm).build();
               DecodedJWT claims= jwtVerifier.verify(Accestoken);
               String username = claims.getSubject();
               String[]  roles= claims.getClaim("roles").asArray(String.class);
               Collection<GrantedAuthority> authorities = new ArrayList<>();
               for(String role: roles) {
                   authorities.add(new SimpleGrantedAuthority(role));
               }
               UsernamePasswordAuthenticationToken authenticationToken= new UsernamePasswordAuthenticationToken(username,null,
                      authorities );
               SecurityContextHolder.getContext().setAuthentication(authenticationToken);
               filterChain.doFilter(request, response);

           }catch (Exception e){
               response.setHeader("error", e.getMessage());
               response.sendError(HttpServletResponse.SC_FORBIDDEN);

           }



        }
    }
}
