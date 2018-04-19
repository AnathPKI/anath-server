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

import ch.zhaw.ba.anath.TestSecuritySetup;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(WhoAmIController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class WhoAmIControllerIT {
    @Autowired
    private MockMvc mvc;

    @MockBean
    private UserRepository userRepository;
    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void whoAmIAsAdmin() throws Exception {
        final UserEntity userEntity = new UserEntity();
        userEntity.setAdmin(true);
        userEntity.setEmail("admin");
        userEntity.setLastname("lastname");
        userEntity.setFirstname("firstname");

        given(userRepository.findOneByEmail("admin")).willReturn(Optional.of(userEntity));
        mvc.perform(
                get("/whoami")
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user", equalTo("admin")))
                .andExpect(jsonPath("$.admin", equalTo(true)))
                .andExpect(jsonPath("$.firstname", equalTo("firstname")))
                .andExpect(jsonPath("$.lastname", equalTo("lastname")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void whoAmIAsUser() throws Exception {
        final UserEntity userEntity = new UserEntity();
        userEntity.setAdmin(false);
        userEntity.setEmail("user");
        userEntity.setLastname("lastname");
        userEntity.setFirstname("firstname");

        given(userRepository.findOneByEmail("user")).willReturn(Optional.of(userEntity));
        mvc.perform(
                get("/whoami")
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user", equalTo("user")))
                .andExpect(jsonPath("$.admin", equalTo(false)))
                .andExpect(jsonPath("$.firstname", equalTo("firstname")))
                .andExpect(jsonPath("$.lastname", equalTo("lastname")));
    }

    @Test
    public void whoAmIAsUnauthenticated() throws Exception {
        mvc.perform(
                get("/whoami")
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
    }
}