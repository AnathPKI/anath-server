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

package ch.zhaw.ba.anath.authentication.users;

import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Rafael Ostertag
 */
public class UserPermissionEvaluatorTest {
    private final static Set<SimpleGrantedAuthority> DEFAULT_USER_ROLES = Collections.singleton(new
            SimpleGrantedAuthority("USER"));
    private static final String TEST_USER_NAME = "testuser";
    private static final String TARGET_TYPE = "user";
    private UserRepository userRepositoryMock;
    private UserPermissionEvaluator userPermissionEvaluator;

    @Before
    public void setUp() {
        this.userRepositoryMock = mock(UserRepository.class);
        this.userPermissionEvaluator = new UserPermissionEvaluator(userRepositoryMock);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void hasPermission3() {
        userPermissionEvaluator.hasPermission(null, null, null);
    }

    @Test
    public void hasPermission4ChangePassword() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = userPermissionEvaluator.hasPermission(authentication, 1L, TARGET_TYPE, "changePassword");
        assertThat(result, is(true));

        result = userPermissionEvaluator.hasPermission(authentication, 2L, TARGET_TYPE, "changePassword");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 3L, TARGET_TYPE, "changePassword");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4GetPermissions() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = userPermissionEvaluator.hasPermission(authentication, 1L, TARGET_TYPE, "get");
        assertThat(result, is(true));

        result = userPermissionEvaluator.hasPermission(authentication, 2L, TARGET_TYPE, "get");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 3L, TARGET_TYPE, "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4UnknownPermission() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = userPermissionEvaluator.hasPermission(authentication, 1L, TARGET_TYPE, "should not exist");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 2L, TARGET_TYPE, "should not exist");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 3L, TARGET_TYPE, "should not exist");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4UnknownTargetType() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = userPermissionEvaluator.hasPermission(authentication, 1L, "should not exist", "get");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 2L, "should not exist", "get");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 3L, "should not exist", "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4InvalidTargetIdType() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = userPermissionEvaluator.hasPermission(authentication, "id", TARGET_TYPE, "get");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, "id", TARGET_TYPE, "get");
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, "id", TARGET_TYPE, "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4InvalidPermissionType() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = userPermissionEvaluator.hasPermission(authentication, 1L, TARGET_TYPE, 1);
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 2L, TARGET_TYPE, 1);
        assertThat(result, is(false));

        result = userPermissionEvaluator.hasPermission(authentication, 3L, TARGET_TYPE, 1);
        assertThat(result, is(false));
    }

    private UsernamePasswordAuthenticationToken setUpTest() {
        final UsernamePasswordAuthenticationToken authentication = setUpTestUser();
        final UserEntity testUserEntity = new UserEntity();
        testUserEntity.setEmail(TEST_USER_NAME);
        final UserEntity otherUserEntity = new UserEntity();
        otherUserEntity.setEmail(TEST_USER_NAME + "other");
        given(userRepositoryMock.findOne(1L)).willReturn(Optional.of(testUserEntity));
        given(userRepositoryMock.findOne(2L)).willReturn(Optional.of(otherUserEntity));
        given(userRepositoryMock.findOne(3L)).willReturn(Optional.empty());
        return authentication;
    }

    private UsernamePasswordAuthenticationToken setUpTestUser() {
        final User testUser = new User(TEST_USER_NAME, "", DEFAULT_USER_ROLES);
        final UsernamePasswordAuthenticationToken authentication = new
                UsernamePasswordAuthenticationToken(testUser, "", DEFAULT_USER_ROLES);

        return authentication;
    }
}