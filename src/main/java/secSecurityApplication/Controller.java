package secSecurityApplication;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sid.AppRole;
import org.sid.AppUser;

import jakarta.servlet.http.HttpServletRequest;

import jakarta.servlet.http.HttpServletResponse
        ;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import service.Service1;

@RestController
public class Controller {
    @Autowired
    private Service1 service ;
    public Controller(Service1 service) {
        this.service = service;
    }
    @GetMapping("/users")
    @PostAuthorize("hasAuthority('apiculteur')")
    public List<AppUser> getUsers() {

        return service.listUsers();
    }
    @PostMapping("/users")
    public AppUser addUser(@RequestBody AppUser user) {

        return service.addNewUser(user);

    }
    @PostMapping("/roles")
    public AppRole addRole(@RequestBody AppRole role) {
        return service.addNewRole(role);
    }
    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody AppRole role, AppUser user) {
        service.addRoleToUser(user,role);
    }
    @GetMapping("RefreshToken")
    public void RefreshToken(HttpServletRequest request, HttpServletResponse response){
        String AccesToken = request.getHeader("Authorization");

        if(AccesToken != null && AccesToken.startsWith("Bearer "
        )) {
            String jwt = AccesToken.substring(7);
            Algorithm alg = Algorithm.HMAC256("ma clé :)");
            try {
                JWTVerifier jwtVerifier = JWT.require(alg).build();
                DecodedJWT claims = jwtVerifier.verify(jwt);
                String username = claims.getSubject();
                AppUser user = service.loadUserByUsername(username);
                Collection<AppRole> roles = user.getRoles();

                Collection<GrantedAuthority> authorities = new ArrayList<>();
                for (AppRole role : roles) {
                    authorities.add(new SimpleGrantedAuthority(role.getDescription()));
                }
                String JWTAccessToken = JWT.create()
                                           .withSubject(user.getUsername())
                                           .withExpiresAt(new Date(System.currentTimeMillis() + 5*60*1000))
                                           .withIssuer(request.getRequestURL().toString())
                                           .withClaim("roles",authorities.stream().map(r->r.getAuthority()).collect(Collectors.toList()))
                                           .sign(alg);

                response.addHeader( "Authorization", "Bearer " +JWTAccessToken);

                Map<String ,String > idTokens= new HashMap<>();
                idTokens.put("AccessToken", JWTAccessToken);
                idTokens.put("RefreshToken", jwt);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getWriter(),idTokens);
            }

        catch (Exception e){
            response.setHeader("error", e.getMessage());

        }}



        }



    }
}
