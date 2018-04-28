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
import ch.zhaw.ba.anath.config.properties.AnathProperties;
import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.SigningService;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;

import static org.hamcrest.Matchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(SigningControllerWithConfirmation.class)
@ActiveProfiles({"tests", "confirm"})
@TestSecuritySetup
public class SigningControllerWithConfirmationIT {
    private static final String THE_TOKEN = "badcaffee";

    @Autowired
    private MockMvc mvc;

    @MockBean
    private SigningService signingService;

    // Required to satisfy injection dependency
    @MockBean
    private UserRepository userRepository;

    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    private Certificate certificate;

    @Before
    public void setUp() {
        final X509CertificateHolder mock = mock(X509CertificateHolder.class);
        this.certificate = new Certificate(mock);
        given(mock.getSerialNumber()).willReturn(BigInteger.valueOf(42));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void signCertificateRequestWithConfirmationAsUser() throws Exception {

        given(signingService.tentativelySignCertificate(Matchers.any(), eq("user"), eq("plain"))).willReturn
                (THE_TOKEN);
        given(signingService.confirmTentativelySignedCertificate(THE_TOKEN, "user")).willReturn(certificate);
        mvc.perform(
                post("/certificates")
                        .content(SigningControllerWithoutConfirmationIT.VALID_CSR_REQUEST_BODY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(jsonPath("$.noLaterThan", is(not(nullValue()))))
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(status().isOk());

        then(signingService).should().tentativelySignCertificate(Matchers.any(), eq("user"), eq("plain"));
        then(signingService).should(never()).confirmTentativelySignedCertificate(anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "user", roles = {"ADMIN"})
    public void signCertificateRequestWithConfirmationAdmin() throws Exception {
        mvc.perform(
                post("/certificates")
                        .content(SigningControllerWithoutConfirmationIT.VALID_CSR_REQUEST_BODY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        then(signingService).should(never()).tentativelySignCertificate(Matchers.any(), anyString(), anyString());
        then(signingService).should(never()).confirmTentativelySignedCertificate(anyString(), anyString());
    }

    @Test
    public void signCertificateRequestWithConfirmationUnauthenticated() throws Exception {
        mvc.perform(
                post("/certificates")
                        .content(SigningControllerWithoutConfirmationIT.VALID_CSR_REQUEST_BODY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());

        then(signingService).should(never()).tentativelySignCertificate(Matchers.any(), anyString(), anyString());
        then(signingService).should(never()).confirmTentativelySignedCertificate(anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void confirmCertificateRequestAsUser() throws Exception {
        given(signingService.confirmTentativelySignedCertificate(THE_TOKEN, "user")).willReturn(certificate);

        mvc.perform(
                put("/certificates/confirm/{token}", THE_TOKEN)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isCreated())
                .andExpect(redirectedUrl("http://localhost/certificates/42"));

        then(signingService).should(never()).tentativelySignCertificate(Matchers.any(), anyString(), anyString());
        then(signingService).should().confirmTentativelySignedCertificate(THE_TOKEN, "user");
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void confirmCertificateRequestAsAdmin() throws Exception {
        mvc.perform(
                put("/certificates/confirm/{token}", THE_TOKEN)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        then(signingService).should(never()).tentativelySignCertificate(Matchers.any(), anyString(), anyString());
        then(signingService).should(never()).confirmTentativelySignedCertificate(anyString(), anyString());
    }

    @Test
    public void confirmCertificateRequestAsUnauthenticate() throws Exception {
        mvc.perform(
                put("/certificates/confirm/{token}", THE_TOKEN)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());

        then(signingService).should(never()).tentativelySignCertificate(Matchers.any(), anyString(), anyString());
        then(signingService).should(never()).confirmTentativelySignedCertificate(anyString(), anyString());
    }

    @TestConfiguration
    static class AnathTestPropertiesConfiguration {
        @Bean
        public AnathProperties anathProperties() {
            return new AnathProperties();
        }
    }
}