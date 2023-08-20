package org.sid.securityservice.web;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public AuthController(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, AuthenticationManager authenticationManager, UserDetailsService userDetailsService, UserDetailsService userDetailsService1) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }
    @PostMapping("/token")
    public Map<String, String> jwtToken(String grantType,
                                        String username,
                                        String password,
                                        boolean withRefreshToken,
                                        String RefreshToken){
        String subject=null;
        String scope=null;


        if(grantType.equals("password")){
            Authentication authentication= authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username,password)
            );
            subject= authentication.getName();
            scope= authentication.getAuthorities()
                    .stream().map(auth->auth.getAuthority())
                    .collect(Collectors.joining(" "));
        }else if(grantType.equals("refreshToken")){
            Jwt decodeJWT =jwtDecoder.decode(RefreshToken);
            subject=decodeJWT.getSubject();
            UserDetails userDetails= userDetailsService.loadUserByUsername(subject);
            Collection<? extends GrantedAuthority> authorities= userDetails.getAuthorities();
            scope=authorities.stream().map(auth->auth.getAuthority()).collect(Collectors.joining(" "));
        }

        Map<String,String> idToken=new HashMap<>();
        Instant instant=Instant.now();
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken?1:5, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",jwtAccessToken);
        if(withRefreshToken){
            JwtClaimsSet jwtClaimsSetRefresh=JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();
            String jwtRefreshToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idToken.put("refreshToken",jwtRefreshToken);
        }
        return idToken;
    }
}
