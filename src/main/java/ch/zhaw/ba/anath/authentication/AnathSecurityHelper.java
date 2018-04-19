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

package ch.zhaw.ba.anath.authentication;

import ch.zhaw.ba.anath.AnathException;
import ch.zhaw.ba.anath.config.properties.AnathProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Helper functions for spring security.
 * @author Rafael Ostertag
 */
@Slf4j
public final class AnathSecurityHelper {
    private AnathSecurityHelper() {
        // intentionally empty
    }

    /**
     * Get the user name from the current security context.
     *
     * @return current user name of the principal.
     */
    public static String getUsername() {
        final Authentication authentication = getAuthenticationObject();
        return getUsername(authentication);
    }

    /**
     * Get the user name from a provided {@link Authentication} instance.
     *
     * @param authentication {@link Authentication} instance.
     *
     * @return user name of the principal.
     */
    public static String getUsername(Authentication authentication) {
        final Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        log.error("Authentication misconfigured. Expected String in security context, " +
                "but got {}", principal.getClass().getName());
        throw new AnathException("Authentication missconfigured");
    }

    private static Authentication getAuthenticationObject() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static byte[] getJwtSecretAsByteArrayOrThrow(AnathProperties.Authentication.JWT jwtProperties) {
        final String jwtSecret = jwtProperties.getSecret();
        if (jwtSecret == null) {
            log.error("Please set '{}.{}'", AnathProperties.CONFIGURATION_PREFIX, "authentication.jwt.secret");
            throw new AnathException("JWT Secret not set");
        }

        return jwtSecret.getBytes();
    }


}
