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
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.CertificateAuthorityService;
import ch.zhaw.ba.anath.pki.services.RevocationService;
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

import static org.hamcrest.Matchers.startsWith;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CertificateAuthorityController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class CertificateAuthorityControllerIT {
    @Autowired
    private MockMvc mvc;

    @MockBean
    private CertificateAuthorityService certificateAuthorityService;

    @MockBean
    private RevocationService revocationService;

    // Required to satisfy injection dependency
    @MockBean
    private UserRepository userRepository;

    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    public void getCaCertificate() throws Exception {
        given(certificateAuthorityService.getCertificate()).willReturn("certificate");

        mvc.perform(
                get("/ca.pem")
        )
                .andExpect(unauthenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(PkixMediaType.APPLICATION_PKIX_CERT_VALUE)));
    }

    @Test
    public void getCaCertificateUnintialized() throws Exception {
        given(certificateAuthorityService.getCertificate()).willThrow(new CertificateAuthorityNotInitializedException
                ("not initialized"));

        mvc.perform(
                get("/ca.pem")
        )
                .andExpect(unauthenticated())
                .andExpect(status().isInternalServerError());
    }

    @Test
    public void getCrl() throws Exception {
        given(revocationService.getCrlPemEncoded()).willReturn("crl");
        mvc.perform(
                get("/crl.pem")
        )
                .andExpect(header().string("Content-Type", startsWith(PkixMediaType.APPLICATION_PKIX_CRL_VALUE)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getCaCertificateWhenAuthenticated() throws Exception {
        given(certificateAuthorityService.getCertificate()).willReturn("certificate");

        mvc.perform(
                get("/ca.pem")
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(PkixMediaType.APPLICATION_PKIX_CERT_VALUE)));
    }
}