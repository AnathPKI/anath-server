/*
 * Copyright (c) 2018, Rafael Ostertag
 * All rights reserved.
 *
 * Redistribution and  use in  source and binary  forms, with  or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.  Redistributions of  source code  must retain  the above  copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in  binary form must reproduce  the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation   and/or   other    materials   provided   with   the
 *    distribution.
 *
 * THIS SOFTWARE  IS PROVIDED BY  THE COPYRIGHT HOLDERS  AND CONTRIBUTORS
 * "AS  IS" AND  ANY EXPRESS  OR IMPLIED  WARRANTIES, INCLUDING,  BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES  OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE  ARE DISCLAIMED. IN NO EVENT  SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL,  EXEMPLARY,  OR  CONSEQUENTIAL DAMAGES  (INCLUDING,  BUT  NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE  GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS  INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF  LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY,  OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package ch.zhaw.ba.anath.authentication.spring;

import ch.zhaw.ba.anath.config.properties.AnathProperties;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * @author Rafael Ostertag
 */
@Slf4j
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    private final UserDetailsService userDetailsService;
    private final AnathProperties.Authentication.JWT jwtProperties;

    public JWTAuthorizationFilter(AuthenticationManager authManager, UserDetailsService userDetailsService,
                                  AnathProperties anathProperties) {
        super(authManager);
        this.userDetailsService = userDetailsService;
        this.jwtProperties = anathProperties.getAuthentication().getJwt();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(JWTConstants.JWT_HEADER);

        if (header == null || !header.startsWith(JWTConstants.TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        Optional<UsernamePasswordAuthenticationToken> authentication = getAuthentication(req);
        authentication.ifPresent(x -> SecurityContextHolder.getContext().setAuthentication(x));

        chain.doFilter(req, res);
    }

    private Optional<UsernamePasswordAuthenticationToken> getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(JWTConstants.JWT_HEADER);
        if (token != null) {
            final byte[] secret = AnathSecurityHelper.getJwtSecretAsByteArrayOrThrow(jwtProperties);
            try {
                String user = Jwts.parser()
                        .setSigningKey(secret)
                        .parseClaimsJws(token.replace(JWTConstants.TOKEN_PREFIX, ""))
                        .getBody()
                        .getSubject();

                if (user != null) {
                    final UserDetails userDetails = userDetailsService.loadUserByUsername(user);
                    return Optional.of(new UsernamePasswordAuthenticationToken(userDetails, "",
                            userDetails.getAuthorities()));
                }
            } catch (ExpiredJwtException e) {
                log.error("The JWT presented is expired", e);
            } catch (JwtException e) {
                log.error("JWT exception: {}", e.getMessage());
            }
            return Optional.empty();
        }
        return Optional.empty();
    }
}
