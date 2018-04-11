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
import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.dto.RevocationReasonDto;
import ch.zhaw.ba.anath.pki.dto.bits.CertificateValidityBit;
import ch.zhaw.ba.anath.pki.dto.bits.PemBit;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.CertificateService;
import ch.zhaw.ba.anath.pki.services.RevocationService;
import ch.zhaw.ba.anath.pki.services.SigningService;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CertificatesController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class CertificatesControllerIT {
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

    private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String DEFAULT_USER_ID = "user";
    @Autowired
    private MockMvc mvc;

    @MockBean
    private CertificateService certificateService;

    @MockBean
    private RevocationService revocationService;

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
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getCertificateAsAdmin() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(MediaType.ALL)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.use", is("plain")))
                .andExpect(jsonPath("$.config", is(nullValue())))
                .andExpect(jsonPath("$.cert.pem", is("PEM goes here")))
                .andExpect(jsonPath("$.validity.revoked", is(false)))
                .andExpect(jsonPath("$.validity.revocationReason", is(nullValue())))
                .andExpect(jsonPath("$.validity.revocationTime", is(nullValue())))
                .andExpect(jsonPath("$.validity.expired", is(false)))
                .andExpect(jsonPath("$.validity.notBefore", is(not(nullValue()))))
                .andExpect(jsonPath("$.validity.notAfter", is(not(nullValue()))))
                .andExpect(jsonPath("$.links[0].rel", is("revoke")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/certificates/1/revoke")))
                .andExpect(jsonPath("$.links[1].rel", is("pem")))
                .andExpect(jsonPath("$.links[1].href", is("http://localhost/certificates/1")));
    }

    @Test
    @WithMockUser(username = DEFAULT_USER_ID, roles = {"USER"})
    public void getCertificateAsUser() throws Exception {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setUserId(DEFAULT_USER_ID);
        given(certificateRepository.findOneBySerial(BigInteger.ONE)).willReturn(Optional.of(certificateEntity));

        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(MediaType.ALL_VALUE)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.use", is("plain")))
                .andExpect(jsonPath("$.config", is(nullValue())))
                .andExpect(jsonPath("$.cert.pem", is("PEM goes here")))
                .andExpect(jsonPath("$.validity.revoked", is(false)))
                .andExpect(jsonPath("$.validity.revocationReason", is(nullValue())))
                .andExpect(jsonPath("$.validity.revocationTime", is(nullValue())))
                .andExpect(jsonPath("$.validity.expired", is(false)))
                .andExpect(jsonPath("$.validity.notBefore", is(not(nullValue()))))
                .andExpect(jsonPath("$.validity.notAfter", is(not(nullValue()))))
                .andExpect(jsonPath("$.links[0].rel", is("revoke")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/certificates/1/revoke")))
                .andExpect(jsonPath("$.links[1].rel", is("pem")))
                .andExpect(jsonPath("$.links[1].href", is("http://localhost/certificates/1")));
    }

    @Test
    @WithMockUser(username = DEFAULT_USER_ID, roles = {"USER"})
    public void getCertificateAsUnauthorizedUser() throws Exception {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setUserId("another user");
        given(certificateRepository.findOneBySerial(BigInteger.ONE)).willReturn(Optional.of(certificateEntity));

        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(MediaType.ALL)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
    }

    @Test
    public void getCertificateAsUnauthenticated() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(MediaType.ALL_VALUE)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getNonExistingCertificate() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willThrow(new CertificateNotFoundException(""));

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(MediaType.ALL_VALUE)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isNotFound());
    }

    private CertificateResponseDto makeCertificateResponseDto() {
        final CertificateResponseDto certificateResponseDto = new CertificateResponseDto();
        certificateResponseDto.setUse("plain");
        final CertificateValidityBit certificateValidityBit = new CertificateValidityBit();
        certificateValidityBit.setRevocationReason(null);
        certificateValidityBit.setRevoked(false);
        certificateValidityBit.setNotBefore(new Date());
        certificateValidityBit.setNotAfter(new Date());
        certificateValidityBit.setExpired(false);
        certificateResponseDto.setValidity(certificateValidityBit);
        final PemBit pemBit = new PemBit();
        pemBit.setPem("PEM goes here");
        certificateResponseDto.setCert(pemBit);
        return certificateResponseDto;
    }

    @Test
    public void getPlainPemCertificateAcceptingAllMediaTypes() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willReturn("certificate");

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .accept(MediaType.ALL)
        )
                .andExpect(header().string("Content-Type", startsWith(PkixMediaType.APPLICATION_PKIX_CERT_VALUE)))
                .andExpect(unauthenticated())
                .andExpect(status().isOk());
    }

    @Test
    public void getPlainPemCertificateAcceptingPkixCert() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willReturn("certificate");

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .accept(PkixMediaType.APPLICATION_PKIX_CERT)
        )
                .andExpect(header().string("Content-Type", startsWith(PkixMediaType.APPLICATION_PKIX_CERT_VALUE)))
                .andExpect(unauthenticated())
                .andExpect(status().isOk());
    }

    @Test
    public void getNonExistingPlainPemCertificate() throws Exception {
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willThrow(new
                CertificateNotFoundException(""));

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(username = DEFAULT_USER_ID, roles = {"USER"})
    public void getPlainPemCertificateAsUser() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willReturn("certificate");

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .accept(MediaType.ALL)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = DEFAULT_USER_ID, roles = {"USER"})
    public void getNonExistingPlainPemCertificateAsUser() throws Exception {
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willThrow(new
                CertificateNotFoundException(""));

        mvc.perform(
                get("/certificates/{serial}/pem", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .accept(MediaType.ALL)
        )
                .andExpect(authenticated())
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getAllAsAdmin() throws Exception {
        testGetAllUsers();
    }

    private void testGetAllUsers() throws Exception {
        final CertificateListItemDto certificateListItemDto = makeCertificateListItemDto();
        doReturn(Collections.singletonList(certificateListItemDto)).when(certificateService).getAll();

        mvc.perform(
                get("/certificates")
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.content[0].subject", is("subject")))
                .andExpect(jsonPath("$.content[0].use", is("plain")))
                .andExpect(jsonPath("$.content[0].valid", is(true)))
                .andExpect(jsonPath("$.content[0].serial", is(1)))
                .andExpect(jsonPath("$.content[0].userId").doesNotExist())
                .andExpect(jsonPath("$.content[0].links[0].rel", is("self")))
                .andExpect(jsonPath("$.content[0].links[0].href", is("http://localhost/certificates/1")))
                .andExpect(jsonPath("$.content[0].links[1].rel", is("pem")))
                .andExpect(jsonPath("$.content[0].links[1].href", is("http://localhost/certificates/1")))
                .andExpect(jsonPath("$.content[0].links[2].rel", is("revoke")))
                .andExpect(jsonPath("$.content[0].links[2].href", is("http://localhost/certificates/1/revoke")))
                .andExpect(jsonPath("$.links[0].rel", is("sign")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/certificates")));
    }

    @Test
    @WithMockUser(username = DEFAULT_USER_ID, roles = {"USER"})
    public void getAllAsUser() throws Exception {
        testGetAllUsers();
    }

    @Test
    @WithMockUser(username = DEFAULT_USER_ID + "another", roles = {"USER"})
    public void getAllAsUserNoUserIdMatching() throws Exception {
        final CertificateListItemDto certificateListItemDto = makeCertificateListItemDto();
        doReturn(Collections.singletonList(certificateListItemDto)).when(certificateService).getAll();

        mvc.perform(
                get("/certificates")
                        .contentType(MediaType.ALL_VALUE)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.content", is(empty())))
                .andExpect(jsonPath("$.links[0].rel", is("sign")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/certificates")));
    }


    @Test
    public void getAllAsUnauthenticated() throws Exception {
        final CertificateListItemDto certificateListItemDto = makeCertificateListItemDto();
        doReturn(Collections.singletonList(certificateListItemDto)).when(certificateService).getAll();

        mvc.perform(
                get("/certificates")
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
    }

    private CertificateListItemDto makeCertificateListItemDto() {
        final CertificateListItemDto certificateListItemDto = new CertificateListItemDto();
        certificateListItemDto.setValid(true);
        certificateListItemDto.setUse("plain");
        certificateListItemDto.setSubject("subject");
        certificateListItemDto.setSerial(BigInteger.ONE);
        certificateListItemDto.setUserId(DEFAULT_USER_ID);
        return certificateListItemDto;
    }

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

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void signCertificateRequestUser() throws Exception {

        given(signingService.signCertificate(Matchers.any(), eq("user"), eq("plain"))).willReturn(certificate);
        mvc.perform(
                post("/certificates")
                        .content(validCsrRequestBody)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(redirectedUrl("http://localhost/certificates/42"))
                .andExpect(header().string("Content-Type", AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE))
                .andExpect(status().isCreated());

        then(signingService).should().signCertificate(Matchers.any(), eq("user"), eq("plain"));
    }

    @Test
    @WithMockUser(username = "user", roles = {"ADMIN"})
    public void signCertificateRequestAdmin() throws Exception {
        mvc.perform(
                post("/certificates")
                        .content(validCsrRequestBody)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        then(signingService).should(never()).signCertificate(Matchers.any(), anyString(), anyString());
    }

    @Test
    public void signCertificateRequestUnauthenticated() throws Exception {
        mvc.perform(
                post("/certificates")
                        .content(validCsrRequestBody)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());

        then(signingService).should(never()).signCertificate(Matchers.any(), anyString(), anyString());
    }
}