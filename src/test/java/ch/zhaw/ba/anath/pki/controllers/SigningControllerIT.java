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

package ch.zhaw.ba.anath.pki.controllers;

import ch.zhaw.ba.anath.TestSecuritySetup;
import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.services.SigningService;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;

import static org.assertj.core.api.BDDAssertions.then;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(SigningController.class)
@TestSecuritySetup
public class SigningControllerIT {
    private static final String validCsrRequestBody = "{ \n" +
            "\"use\" : \"plain\",\n" +
            "\"csr\": { \n" +
            "\"pem\": \"-----BEGIN CERTIFICATE " +
            "REQUEST-----\\nMIICuTCCAaECAQAwdDELMAkGA1UEBhMCQ0gxEDAOBgNVBAcMB0tlZmlrb24xGDAW" +
            "\\nBgNVBAoMD1JhZmFlbCBPc3RlcnRhZzEWMBQGA1UEAwwNSmFtZXMgVC4gS2lyazEh" +
            "\\nMB8GCSqGSIb3DQEJARYSa2lya0BzdGFyZmxlZXQub3JnMIIBIjANBgkqhkiG9w0B" +
            "\\nAQEFAAOCAQ8AMIIBCgKCAQEA0lPxrehKFlclL7WAAg2wq/cslbsG4f89DrovcDIB\\n9gNkQCI7g4e2Ug3ePoYxgpFIbPyij" +
            "/PGNiIyGZkTc9UeEWPOofPsjsfxuv8wS+7K\\nPadMDQREx2DurDz9Y04VjswZylc//C4+5whpCHQG/HDDczXjoilwBlDf7DiiFf7y" +
            "\\nesRTKV4qLuGZBZstAAsboYDnU2dat8Z9zKh/LDcaoEUq74KEsKfHnKtKpYrx7G+0\\nAqIQw" +
            "/wVfY4HJ36RMzxkTJ4Wo7CBl5ajFRMYFyGysmzEkPMw0pBc6D7O3XJAz42G\\n9rz36CDRcYRTWQST7eTd7C12C/SlGw" +
            "/mxkRJk1j23NWALwIDAQABoAAwDQYJKoZI\\nhvcNAQELBQADggEBACU7Pavqj8F9TlUYk0fh5PeeWFuB0gpSreZVkS9o94BqLmZj" +
            "\\nORPOmuBVdRDxFRiUrfpvH+UQVEFGr0MG2HJL0+w0iaWBCh5i8CRq9gUy6cc1nY2w\\nHTxv7f89w" +
            "+OHKU3gp3wzNmuLfUXOQEG672ipxnMtjblrxEPdxmFk3g1rQszd/GIR\\n7QIDL/HVGbMcZygLuju1rFNdUQai225ESuHIfj1H83mv" +
            "/SCVonCAxMlTx2qoU+oP\\nyabimYxNHbV6TH1lLkJDf4TiCCfYvV2BPAyKLnX6ErVH0ICW0SWqsjXr2EU6HNCH\\nLAa+ODNGcY7CZm" +
            "/qqEndkPX6zk6VKba2DKGiISY=\\n-----END CERTIFICATE REQUEST-----\"\n" +
            "}\n" +
            "}";

    @Autowired
    private MockMvc mvc;

    @MockBean
    private SigningService signingService;

    @MockBean
    private UserRepository userRepository;

    private Certificate certificate;

    @Before
    public void setUp() {
        final X509CertificateHolder mock = mock(X509CertificateHolder.class);
        this.certificate = new Certificate(mock);
        given(mock.getSerialNumber()).willReturn(BigInteger.valueOf(42));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void signCertificateRequestUser() throws Exception {

        given(signingService.signCertificate(any(), eq("user"), eq("plain"))).willReturn(certificate);
        mvc.perform(
                post("/sign")
                        .content(validCsrRequestBody)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(redirectedUrl("http://localhost/certificates/42"))
                .andExpect(header().string("Content-Type", AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE))
                .andExpect(status().isCreated());

        then(signingService.signCertificate(any(), eq("user"), eq("plain")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"ADMIN"})
    public void signCertificateRequestAdmin() throws Exception {
        mvc.perform(
                post("/sign")
                        .content(validCsrRequestBody)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        verify(signingService, never()).signCertificate(any(), anyString(), anyString());
    }

    @Test
    public void signCertificateRequestUnauthenticated() throws Exception {
        mvc.perform(
                post("/sign")
                        .content(validCsrRequestBody)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());

        verify(signingService, never()).signCertificate(any(), anyString(), anyString());
    }
}