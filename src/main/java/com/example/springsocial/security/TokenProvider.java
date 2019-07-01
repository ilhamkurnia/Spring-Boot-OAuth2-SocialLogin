package com.example.springsocial.security;

import com.example.springsocial.config.AppProperties;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties){
        this.appProperties = appProperties;
    }

    public String createToken(Authentication authentication){
        UserPrincipal userPrincipal = (UserPrincipal)authentication.getPrincipal();

        Date now = new Date();
        Date expireDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
                .compact();
    }

    public Long getUserIdFromToken(String token){
        Claims claims =Jwts.parser()
                .setSigningKey(appProperties.getAuth().getTokenSecret())
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken){
        try {
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(authToken);
            return true;
        }catch (SignatureException ex){
            logger.error("Invalid JWT Signature");
        }catch (MalformedJwtException ex){
            logger.error("Invalid JWT Token");
        }catch (ExpiredJwtException ex){
            logger.error("Expired JWT Token");
        }catch(UnsupportedJwtException ex){
            logger.error("Unsupported JWT Token");
        }catch (IllegalArgumentException ex){
            logger.error("JWT claims string is empty.");
        }

        return false;
    }
}
