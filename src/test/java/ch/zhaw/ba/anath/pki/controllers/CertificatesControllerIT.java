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
import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.dto.bits.CertificateValidityBit;
import ch.zhaw.ba.anath.pki.dto.bits.PemBit;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.CertificateService;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CertificatesController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class CertificatesControllerIT {
    @Autowired
    private MockMvc mvc;

    @MockBean
    private CertificateService certificateService;

    // Required to satisfy injection dependency
    @MockBean
    private UserRepository userRepository;

    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getCertificateAsAdmin() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
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
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/revoke/1")))
                .andExpect(jsonPath("$.links[1].rel", is("pem")))
                .andExpect(jsonPath("$.links[1].href", is("http://localhost/certificates/1/pem")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getCertificateAsUser() throws Exception {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setUserId("user");
        given(certificateRepository.findOneBySerial(BigInteger.ONE)).willReturn(Optional.of(certificateEntity));

        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
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
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/revoke/1")))
                .andExpect(jsonPath("$.links[1].rel", is("pem")))
                .andExpect(jsonPath("$.links[1].href", is("http://localhost/certificates/1/pem")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getCertificateAsUnauthorizedUser() throws Exception {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setUserId("another user");
        given(certificateRepository.findOneBySerial(BigInteger.ONE)).willReturn(Optional.of(certificateEntity));

        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getCertificate(BigInteger.ONE)).willReturn(certificateResponseDto);

        mvc.perform(
                get("/certificates/{serial}", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
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
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
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
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
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
    public void getPlainPemCertificate() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willReturn("certificate");

        mvc.perform(
                get("/certificates/{serial}/pem", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
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
                get("/certificates/{serial}/pem", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getPlainPemCertificateAsUser() throws Exception {
        final CertificateResponseDto certificateResponseDto = makeCertificateResponseDto();
        given(certificateService.getPlainPEMEncodedCertificate(BigInteger.ONE)).willReturn("certificate");

        mvc.perform(
                get("/certificates/{serial}/pem", BigInteger.ONE)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .accept(MediaType.ALL)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
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
                .andExpect(jsonPath("$.content[0].links[1].href", is("http://localhost/certificates/1/pem")))
                .andExpect(jsonPath("$.content[0].links[2].rel", is("revoke")))
                .andExpect(jsonPath("$.content[0].links[2].href", is("http://localhost/revoke/1")))
                .andExpect(jsonPath("$.links[0].rel", is("sign")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/sign")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getAllAsUser() throws Exception {
        testGetAllUsers();
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
        certificateListItemDto.setUserId("user");
        return certificateListItemDto;
    }
}