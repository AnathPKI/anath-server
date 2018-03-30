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

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * @author Rafael Ostertag
 */
@Service
@Slf4j
public class AnathUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) {
        if (username.equals("test")) {
            return new User("test", "$argon2i$v=19$m=128000,t=40," +
                    "p=4$cMtaX0OSd4G0rfeAItgQ9w$XvgV1jZ6cHH3FBZwM8KutOHwExZbkO7LMCpjikA2Xg4", Collections
                    .singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        }
        if (username.equals("admin")) {
            return new User("admin", "$argon2i$v=19$m=128000,t=40," +
                    "p=4$cMtaX0OSd4G0rfeAItgQ9w$XvgV1jZ6cHH3FBZwM8KutOHwExZbkO7LMCpjikA2Xg4", Collections
                    .singletonList(new SimpleGrantedAuthority("ROLE_ADMIN")));
        }

        log.error("User '{}' not found", username);
        throw new UsernameNotFoundException("Not found");
    }
}
