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
import ch.zhaw.ba.anath.pki.dto.UpdateUseDto;
import ch.zhaw.ba.anath.pki.dto.UseDto;
import ch.zhaw.ba.anath.pki.dto.UseItemDto;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.UseService;
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

import java.util.Collections;

import static org.hamcrest.Matchers.startsWith;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(UsesController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class UsesControllerIT {
    private static final String TEST_KEY = "test.key";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    @Autowired
    private MockMvc mvc;
    @MockBean
    private UseService useService;
    // Required to satisfy injection dependency
    @MockBean
    private UserRepository userRepository;
    // Required to satisfy injection dependency
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getAllAsAdmin() throws Exception {
        given(useService.getAll()).willReturn(Collections.emptyList());

        mvc.perform(
                get("/uses")
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getAllAsUser() throws Exception {
        given(useService.getAll()).willReturn(Collections.emptyList());

        mvc.perform(
                get("/uses")
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(status().isOk());
    }

    @Test
    public void getAllAsUnauthenticated() throws Exception {
        given(useService.getAll()).willReturn(Collections.emptyList());

        mvc.perform(
                get("/uses")
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getUseAsAdmin() throws Exception {
        given(useService.getUse(TEST_KEY)).willReturn(new UseDto());

        mvc.perform(
                get("/uses/{key}", TEST_KEY)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getUseAsUser() throws Exception {
        given(useService.getUse(TEST_KEY)).willReturn(new UseDto());

        mvc.perform(
                get("/uses/{key}", TEST_KEY)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        verify(useService, never()).getUse(anyString());
    }

    @Test
    public void getUseAsUnauthenticated() throws Exception {
        given(useService.getUse(TEST_KEY)).willReturn(new UseDto());

        mvc.perform(
                get("/uses/{key}", TEST_KEY)
                        .accept(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        verify(useService, never()).getUse(anyString());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void createUseAsAdmin() throws Exception {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_KEY);
        useDto.setConfiguration("configuration");

        given(useService.create(any())).willReturn(new UseItemDto());

        mvc.perform(
                post("/uses")
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(useDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "http://localhost/uses/test.key"));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void createUseAsUser() throws Exception {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_KEY);
        useDto.setConfiguration("configuration");

        given(useService.create(any())).willReturn(new UseItemDto());

        mvc.perform(
                post("/uses")
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(useDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        verify(useService, never()).create(any());
    }

    @Test
    public void createUseAsUnauthenticated() throws Exception {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_KEY);
        useDto.setConfiguration("configuration");

        given(useService.create(any())).willReturn(new UseItemDto());

        mvc.perform(
                post("/uses")
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(useDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        verify(useService, never()).create(any());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void updateUseAsAdmin() throws Exception {
        final UpdateUseDto updateUseDto = new UpdateUseDto();
        updateUseDto.setConfiguration(null);

        given(useService.updateUse(TEST_KEY, null)).willReturn(new UseItemDto());

        mvc.perform(
                put("/uses/{key}", TEST_KEY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(updateUseDto))
        )
                .andExpect(authenticated())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void updateUseAsUser() throws Exception {
        final UpdateUseDto updateUseDto = new UpdateUseDto();
        updateUseDto.setConfiguration(null);

        given(useService.updateUse(TEST_KEY, null)).willReturn(new UseItemDto());

        mvc.perform(
                put("/uses/{key}", TEST_KEY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(updateUseDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        verify(useService, never()).updateUse(anyString(), anyString());
    }

    @Test
    public void updateAsUnauthenticated() throws Exception {
        final UpdateUseDto updateUseDto = new UpdateUseDto();
        updateUseDto.setConfiguration(null);

        given(useService.updateUse(TEST_KEY, null)).willReturn(new UseItemDto());

        mvc.perform(
                put("/uses/{key}", TEST_KEY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(updateUseDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());

        verify(useService, never()).updateUse(anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void deleteUseAsAdmin() throws Exception {
        mvc.perform(
                delete("/uses/{key}", TEST_KEY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(header().string("Content-Type", startsWith(AnathMediaType
                        .APPLICATION_VND_ANATH_V1_JSON_VALUE)))
                .andExpect(status().isOk());
        verify(useService).delete(TEST_KEY);
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void deleteUseAsUser() throws Exception {
        mvc.perform(
                delete("/uses/{key}", TEST_KEY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        verify(useService, never()).delete(anyString());
    }

    @Test
    public void deleteUseAsUnauthenticated() throws Exception {
        mvc.perform(
                delete("/uses/{key}", TEST_KEY)
                        .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        verify(useService, never()).delete(anyString());
    }
}