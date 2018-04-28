/*
 * Copyright (c) 2018, Rafael Ostertag, Martin Wittwer
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

package ch.zhaw.ba.anath.pki.controllers;

import ch.zhaw.ba.anath.TestSecuritySetup;
import ch.zhaw.ba.anath.pki.dto.RevocationReasonDto;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.RevocationService;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;

import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.never;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(RevocationController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class RevocationControllerIT {
    private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @MockBean
    private RevocationService revocationService;

    // Required to satisfy injection dependency
    @MockBean
    private UserRepository userRepository;

    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void revokeAsAdmin() throws Exception {
        final RevocationReasonDto revocationReasonDto = new RevocationReasonDto();
        revocationReasonDto.setReason("test");

        mvc.perform(
                put("/certificates/{serial}/revoke", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(revocationReasonDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isOk());

        then(revocationService).should().revokeCertificate(BigInteger.ONE, "test");
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void revokeAsUser() throws Exception {

        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setUserId("user");
        given(certificateRepository.findOneBySerial(BigInteger.ONE)).willReturn(java.util.Optional.of
                (certificateEntity));

        final RevocationReasonDto revocationReasonDto = new RevocationReasonDto();
        revocationReasonDto.setReason("test");

        mvc.perform(
                put("/certificates/{serial}/revoke", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(revocationReasonDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isOk());

        then(revocationService).should().revokeCertificate(BigInteger.ONE, "test");
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void revokeAsUserNotAuthorized() throws Exception {

        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setUserId("another user");
        given(certificateRepository.findOneBySerial(BigInteger.ONE)).willReturn(java.util.Optional.of
                (certificateEntity));

        final RevocationReasonDto revocationReasonDto = new RevocationReasonDto();
        revocationReasonDto.setReason("test");

        mvc.perform(
                put("/certificates/{serial}/revoke", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(revocationReasonDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        then(revocationService).should(never()).revokeCertificate(Matchers.any(), anyString());
    }

    @Test
    public void revokeAsUnauthenticated() throws Exception {
        final RevocationReasonDto revocationReasonDto = new RevocationReasonDto();
        revocationReasonDto.setReason("test");

        mvc.perform(
                put("/certificates/{serial}/revoke", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(revocationReasonDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());

        then(revocationService).should(never()).revokeCertificate(Matchers.any(), anyString());
    }
}