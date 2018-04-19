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

import ch.zhaw.ba.anath.AnathExtensionMediaType;
import ch.zhaw.ba.anath.TestSecuritySetup;
import ch.zhaw.ba.anath.pki.dto.CreateSelfSignedCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.dto.ImportCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityAlreadyInitializedException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityInitializationException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.CertificateAuthorityInitializationService;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(CertificateAuthorityInitializationController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class CertificateAuthorityInitializationControllerIT {
    private final static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @MockBean
    private CertificateAuthorityInitializationService certificateAuthorityInitializationService;

    // Required to satisfy injection dependency
    @MockBean
    private UserRepository userRepository;

    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void importCaAsAdmin() throws Exception {
        final ImportCertificateAuthorityDto importCertificateAuthorityDto = new ImportCertificateAuthorityDto();
        importCertificateAuthorityDto.setPassword("");
        importCertificateAuthorityDto.setPkcs12("bla");
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(importCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isCreated())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(header().string("Location", "http://localhost/ca.pem"));
        then(certificateAuthorityInitializationService).should().importPkcs12CertificateAuthority
                (importCertificateAuthorityDto);
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void importCaAlreadyExistingAsAdmin() throws Exception {
        doThrow(new CertificateAuthorityAlreadyInitializedException("already initialized"))
                .when(certificateAuthorityInitializationService).importPkcs12CertificateAuthority(any());

        final ImportCertificateAuthorityDto importCertificateAuthorityDto = new ImportCertificateAuthorityDto();
        importCertificateAuthorityDto.setPassword("");
        importCertificateAuthorityDto.setPkcs12("bla");
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(importCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isConflict());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void importCaImportExceptionAsAdmin() throws Exception {
        doThrow(new CertificateAuthorityInitializationException("import exception"))
                .when(certificateAuthorityInitializationService).importPkcs12CertificateAuthority(any());

        final ImportCertificateAuthorityDto importCertificateAuthorityDto = new ImportCertificateAuthorityDto();
        importCertificateAuthorityDto.setPassword("");
        importCertificateAuthorityDto.setPkcs12("bla");
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(importCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isInternalServerError());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void importCaAsUser() throws Exception {
        final ImportCertificateAuthorityDto importCertificateAuthorityDto = new ImportCertificateAuthorityDto();
        importCertificateAuthorityDto.setPassword("");
        importCertificateAuthorityDto.setPkcs12("bla");
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(importCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(certificateAuthorityInitializationService).should(never()).importPkcs12CertificateAuthority(any());
    }

    @Test
    public void importCaAsUnauthenticated() throws Exception {
        final ImportCertificateAuthorityDto importCertificateAuthorityDto = new ImportCertificateAuthorityDto();
        importCertificateAuthorityDto.setPassword("");
        importCertificateAuthorityDto.setPkcs12("bla");
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(importCertificateAuthorityDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(certificateAuthorityInitializationService).should(never()).importPkcs12CertificateAuthority(any());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void createSelfSignedWithInvalidDtoAsAdmin() throws Exception {
        final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto = new
                CreateSelfSignedCertificateAuthorityDto();
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createSelfSignedCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void createSelfSignedValidationErrorAsDto() throws Exception {
        final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto = new
                CreateSelfSignedCertificateAuthorityDto();
        createSelfSignedCertificateAuthorityDto.setBits(512);
        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createSelfSignedCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void createSelfSignedWithMinimumDtoAsAdmin() throws Exception {
        final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto = new
                CreateSelfSignedCertificateAuthorityDto();
        createSelfSignedCertificateAuthorityDto.setBits(1024);
        createSelfSignedCertificateAuthorityDto.setValidDays(180);
        createSelfSignedCertificateAuthorityDto.setOrganization("o");
        createSelfSignedCertificateAuthorityDto.setCommonName("cn");

        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createSelfSignedCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isCreated())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(header().string("Location", "http://localhost/ca.pem"));
        then(certificateAuthorityInitializationService).should().createSelfSignedCertificateAuthority
                (createSelfSignedCertificateAuthorityDto);
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void createSelfSignedAsUser() throws Exception {
        final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto = new
                CreateSelfSignedCertificateAuthorityDto();
        createSelfSignedCertificateAuthorityDto.setBits(1024);
        createSelfSignedCertificateAuthorityDto.setValidDays(180);
        createSelfSignedCertificateAuthorityDto.setOrganization("o");
        createSelfSignedCertificateAuthorityDto.setCommonName("cn");

        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createSelfSignedCertificateAuthorityDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(certificateAuthorityInitializationService).should(never()).createSelfSignedCertificateAuthority(any());
    }

    @Test
    public void createSelfSignedAsUnauthenticated() throws Exception {
        final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto = new
                CreateSelfSignedCertificateAuthorityDto();
        createSelfSignedCertificateAuthorityDto.setBits(1024);
        createSelfSignedCertificateAuthorityDto.setValidDays(180);
        createSelfSignedCertificateAuthorityDto.setOrganization("o");
        createSelfSignedCertificateAuthorityDto.setCommonName("cn");

        mvc.perform(
                put("/")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createSelfSignedCertificateAuthorityDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(certificateAuthorityInitializationService).should(never()).createSelfSignedCertificateAuthority(any());
    }
}