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

package ch.zhaw.ba.anath.users.controllers;

import ch.zhaw.ba.anath.AnathExtensionMediaType;
import ch.zhaw.ba.anath.TestHelper;
import ch.zhaw.ba.anath.TestSecuritySetup;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.services.RevocationService;
import ch.zhaw.ba.anath.users.dto.*;
import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import ch.zhaw.ba.anath.users.services.UserService;
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
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.never;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@WebMvcTest(UserController.class)
@ActiveProfiles("tests")
@TestSecuritySetup
public class UserControllerIT {
    private static final String LASTNAME = "lastname";
    private static final String FIRSTNAME = "firstname";
    private static final String EMAIL = "email";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String OLD_PASSWORD = "old password";
    private static final String NEW_PASSWORD = "new password";
    @Autowired
    private MockMvc mvc;
    @MockBean
    private UserService userService;

    @MockBean
    private RevocationService revocationService;

    @MockBean
    private UserRepository userRepository;

    // Required to satisfy dependency injection
    @MockBean
    private CertificateRepository certificateRepository;

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getAllAsAdmin() throws Exception {
        final UserLinkDto userLinkDto = makeLinkUserDto();
        final List<UserLinkDto> singleton = Collections.singletonList(userLinkDto);
        given(userService.getAll()).willReturn(singleton);

        mvc.perform(
                get("/users")
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].links[0].rel", is("self")))
                .andExpect(jsonPath("$.content[0].links[0].href", is("http://localhost/users/1")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getAllAsUser() throws Exception {
        mvc.perform(
                get("/users")
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(userService).should(never()).getAll();
    }

    @Test
    public void getAllAsUnauthenticated() throws Exception {
        mvc.perform(
                get("/users")
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(userService).should(never()).getAll();
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void getUserAsAdmin() throws Exception {
        final UserDto userDto = makeUserDto();

        given(userService.getUser(1L)).willReturn(userDto);

        mvc.perform(
                get("/users/{id}", 1L)
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.admin", is(false)))
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.lastname", is(LASTNAME)))
                .andExpect(jsonPath("$.firstname", is(FIRSTNAME)))
                .andExpect(jsonPath("$.email", is(EMAIL)))
                .andExpect(jsonPath("$.links[0].rel", is("self")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/users/1")));
    }

    private UserDto makeUserDto() {
        final UserDto userDto = new UserDto();
        userDto.setAdmin(false);
        userDto.setEmail(EMAIL);
        userDto.setFirstname(FIRSTNAME);
        userDto.setLastname(LASTNAME);
        userDto.setUserId(1L);
        return userDto;
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getUserAsUserAuthorized() throws Exception {
        final UserDto userDto = makeUserDto();

        given(userService.getUser(1L)).willReturn(userDto);
        final UserEntity userEntity = new UserEntity();
        // This must match with the user name.
        userEntity.setEmail("user");

        given(userRepository.findOne(1L)).willReturn(Optional.of(userEntity));

        mvc.perform(
                get("/users/{id}", 1L)
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.admin", is(false)))
                .andExpect(jsonPath("$.id", is(1)))
                .andExpect(jsonPath("$.lastname", is(LASTNAME)))
                .andExpect(jsonPath("$.firstname", is(FIRSTNAME)))
                .andExpect(jsonPath("$.email", is(EMAIL)))
                .andExpect(jsonPath("$.links[0].rel", is("self")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/users/1")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getNonExistingUserAsUser() throws Exception {
        final UserDto userDto = makeUserDto();

        given(userService.getUser(1L)).willReturn(userDto);

        given(userRepository.findOne(1L)).willReturn(Optional.empty());

        mvc.perform(
                get("/users/{id}", 1L)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user2", roles = {"USER"})
    public void getUserAsUserUnauthorized() throws Exception {
        final UserDto userDto = makeUserDto();

        given(userService.getUser(1L)).willReturn(userDto);
        final UserEntity userEntity = new UserEntity();
        // This must match with the user name.
        userEntity.setEmail("user");

        given(userRepository.findOne(1L)).willReturn(Optional.of(userEntity));

        mvc.perform(
                get("/users/{id}", 1L)
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(userService).should(never()).getUser(anyLong());
    }

    @Test
    public void getUserUnauthenticated() throws Exception {
        mvc.perform(
                get("/users/{id}", 1L)
                        .accept(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(userService).should(never()).getUser(anyLong());
    }

    private UserLinkDto makeLinkUserDto() {
        final UserLinkDto userLinkDto = new UserLinkDto();
        userLinkDto.setEmail(EMAIL);
        userLinkDto.setUserId(1);
        return userLinkDto;
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void updateUserAsAdmin() throws Exception {
        final UpdateUserDto updateUserDto = makeUpdateUserDto();

        final UserLinkDto userLinkDto = makeLinkUserDto();

        given(userService.updateUser(1L, updateUserDto)).willReturn(userLinkDto);

        mvc.perform(
                put("/users/{id}", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(updateUserDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.links[0].rel", is("self")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/users/1")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void updateUserAsUser() throws Exception {
        final UpdateUserDto updateUserDto = makeUpdateUserDto();

        mvc.perform(
                put("/users/{id}", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(updateUserDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(userService).should(never()).updateUser(anyLong(), any());
    }

    @Test
    public void updateUserUnauthenticated() throws Exception {
        final UpdateUserDto updateUserDto = makeUpdateUserDto();

        mvc.perform(
                put("/users/{id}", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(updateUserDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(userService).should(never()).updateUser(anyLong(), any());
    }

    private UpdateUserDto makeUpdateUserDto() {
        final UpdateUserDto updateUserDto = new UpdateUserDto();
        updateUserDto.setFirstname(FIRSTNAME);
        updateUserDto.setLastname(LASTNAME);
        updateUserDto.setAdmin(true);
        return updateUserDto;
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void deleteUserAsAdmin() throws Exception {
        final UserDto userDto = new UserDto();
        userDto.setEmail(TestHelper.TEST_USER_ID);
        given(userService.getUser(1)).willReturn(userDto);

        mvc.perform(
                delete("/users/{id}", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.links[0].rel", is("list")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/users")));
        then(userService).should().deleteUser(1L);
        then(revocationService).should().revokeAllCertificatesByUser(TestHelper.TEST_USER_ID, "User deleted");
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void deleteUserAsUser() throws Exception {
        mvc.perform(
                delete("/users/{id}", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(userService).should(never()).deleteUser(anyLong());
        then(revocationService).should(never()).revokeAllCertificatesByUser(anyString(), anyString());
    }

    @Test
    public void deleteUserUnatheticated() throws Exception {
        mvc.perform(
                delete("/users/{id}", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(userService).should(never()).deleteUser(anyLong());
        then(revocationService).should(never()).revokeAllCertificatesByUser(anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void changePasswordAsAdmin() throws Exception {
        final ChangePasswordDto changePasswordDto = new ChangePasswordDto();
        changePasswordDto.setOldPassword(OLD_PASSWORD);
        changePasswordDto.setNewPassword(NEW_PASSWORD);

        mvc.perform(
                put("/users/{id}/password", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(changePasswordDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());

        then(userService).should(never()).changePassword(anyLong(), any());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void changePasswordAsUserAuthorized() throws Exception {
        final ChangePasswordDto changePasswordDto = new ChangePasswordDto();
        changePasswordDto.setOldPassword(OLD_PASSWORD);
        changePasswordDto.setNewPassword(NEW_PASSWORD);

        final UserLinkDto userLinkDto = makeLinkUserDto();

        given(userService.changePassword(1L, changePasswordDto)).willReturn(userLinkDto);

        final UserEntity userEntity = new UserEntity();
        // This must match with the user name.
        userEntity.setEmail("user");
        given(userRepository.findOne(1L)).willReturn(Optional.of(userEntity));

        mvc.perform(
                put("/users/{id}/password", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(changePasswordDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", startsWith(AnathExtensionMediaType
                        .APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE)))
                .andExpect(jsonPath("$.links[0].rel", is("self")))
                .andExpect(jsonPath("$.links[0].href", is("http://localhost/users/1")));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void changePasswordForNonExistingUserAsUser() throws Exception {
        final ChangePasswordDto changePasswordDto = new ChangePasswordDto();
        changePasswordDto.setOldPassword(OLD_PASSWORD);
        changePasswordDto.setNewPassword(NEW_PASSWORD);

        final UserLinkDto userLinkDto = makeLinkUserDto();

        given(userService.changePassword(1L, changePasswordDto)).willReturn(userLinkDto);

        given(userRepository.findOne(1L)).willReturn(Optional.empty());

        mvc.perform(
                put("/users/{id}/password", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(changePasswordDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user2", roles = {"USER"})
    public void changePasswordAsUserUnauthorized() throws Exception {
        final ChangePasswordDto changePasswordDto = new ChangePasswordDto();
        changePasswordDto.setOldPassword(OLD_PASSWORD);
        changePasswordDto.setNewPassword(NEW_PASSWORD);

        final UserLinkDto userLinkDto = makeLinkUserDto();

        given(userService.changePassword(1L, changePasswordDto)).willReturn(userLinkDto);

        final UserEntity userEntity = new UserEntity();
        // This must match with the user name.
        userEntity.setEmail("user");
        given(userRepository.findOne(1L)).willReturn(Optional.of(userEntity));

        mvc.perform(
                put("/users/{id}/password", 1)
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(changePasswordDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    public void createUserAsAdmin() throws Exception {
        final CreateUserDto createUserDto = makeCreateUserDto();

        final UserLinkDto userLinkDto = makeLinkUserDto();
        given(userService.createUser(createUserDto)).willReturn(userLinkDto);

        mvc.perform(
                post("/users")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createUserDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "http://localhost/users/1"));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void createUserAsUser() throws Exception {
        final CreateUserDto createUserDto = makeCreateUserDto();

        mvc.perform(
                post("/users")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createUserDto))
        )
                .andExpect(authenticated())
                .andExpect(status().isForbidden());
        then(userService).should(never()).createUser(any());
    }

    @Test
    public void createUserUnauthenticated() throws Exception {
        final CreateUserDto createUserDto = makeCreateUserDto();

        mvc.perform(
                post("/users")
                        .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                        .content(OBJECT_MAPPER.writeValueAsBytes(createUserDto))
        )
                .andExpect(unauthenticated())
                .andExpect(status().isUnauthorized());
        then(userService).should(never()).createUser(any());
    }

    private CreateUserDto makeCreateUserDto() {
        final CreateUserDto createUserDto = new CreateUserDto();
        createUserDto.setAdmin(false);
        createUserDto.setEmail(EMAIL);
        createUserDto.setFirstname(FIRSTNAME);
        createUserDto.setLastname(LASTNAME);
        createUserDto.setPassword(NEW_PASSWORD);
        return createUserDto;
    }
}