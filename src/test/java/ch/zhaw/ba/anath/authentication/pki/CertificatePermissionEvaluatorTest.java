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

package ch.zhaw.ba.anath.authentication.pki;

import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Rafael Ostertag
 */
public class CertificatePermissionEvaluatorTest {
    private static final String TARGET_TYPE = "certificate";
    private final static Set<SimpleGrantedAuthority> DEFAULT_USER_ROLES = Collections.singleton(new
            SimpleGrantedAuthority(TARGET_TYPE));
    private static final String TEST_USER_NAME = "testuser";
    private CertificateRepository certificateRepositoryMock;
    private CertificatePermissionEvaluator certificatePermissionEvaluator;

    @Before
    public void setUp() {
        this.certificateRepositoryMock = mock(CertificateRepository.class);
        this.certificatePermissionEvaluator = new CertificatePermissionEvaluator(certificateRepositoryMock);
    }

    @Test
    public void hasPermission3AnyObject() {
        final boolean result = certificatePermissionEvaluator.hasPermission(null, new Object(), null);
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission3PermissionNonString() {
        final boolean result = certificatePermissionEvaluator.hasPermission(null, new CertificateListItemDto(), 3);
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission3UnknownPermission() {
        final boolean result = certificatePermissionEvaluator.hasPermission(null, new CertificateListItemDto(),
                "should not exist");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission3NullUserId() {
        final boolean result = certificatePermissionEvaluator.hasPermission(null, new CertificateListItemDto(), "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission3GetAndUserIdMatch() {
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = setUpTest();
        final CertificateListItemDto certificateListItemDto = new CertificateListItemDto();
        certificateListItemDto.setUserId(TEST_USER_NAME);
        final boolean result = certificatePermissionEvaluator.hasPermission(usernamePasswordAuthenticationToken,
                certificateListItemDto,
                "get");
        assertThat(result, is(true));
    }

    @Test
    public void hasPermission3RevokeAndUserIdMatch() {
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = setUpTest();
        final CertificateListItemDto certificateListItemDto = new CertificateListItemDto();
        certificateListItemDto.setUserId(TEST_USER_NAME);
        final boolean result = certificatePermissionEvaluator.hasPermission(usernamePasswordAuthenticationToken,
                certificateListItemDto,
                "revoke");
        assertThat(result, is(true));
    }

    @Test
    public void hasPermission3GetAndUserIdNonMatch() {
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = setUpTest();
        final CertificateListItemDto certificateListItemDto = new CertificateListItemDto();
        certificateListItemDto.setUserId(TEST_USER_NAME + " another");
        final boolean result = certificatePermissionEvaluator.hasPermission(usernamePasswordAuthenticationToken,
                certificateListItemDto,
                "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission3RevokeAndUserIdNonMatch() {
        final UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = setUpTest();
        final CertificateListItemDto certificateListItemDto = new CertificateListItemDto();
        certificateListItemDto.setUserId(TEST_USER_NAME + " another");
        final boolean result = certificatePermissionEvaluator.hasPermission(usernamePasswordAuthenticationToken,
                certificateListItemDto,
                "revoke");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4Revoke() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ZERO, TARGET_TYPE,
                "revoke");
        assertThat(result, is(true));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ONE, TARGET_TYPE, "revoke");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.TEN, TARGET_TYPE, "revoke");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4GetPermissions() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ZERO, TARGET_TYPE,
                "get");
        assertThat(result, is(true));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ONE, TARGET_TYPE, "get");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.TEN, TARGET_TYPE, "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4UnknownPermission() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ZERO, TARGET_TYPE,
                "should not exist");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ONE, TARGET_TYPE, "should " +
                "not exist");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.TEN, TARGET_TYPE, "should " +
                "not exist");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4UnknownTargetType() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ZERO, "should not " +
                "exist", "get");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ONE, "should not exist",
                "get");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.TEN, "should not exist",
                "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4InvalidTargetIdType() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = certificatePermissionEvaluator.hasPermission(authentication, "id", TARGET_TYPE, "get");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, "id", TARGET_TYPE, "get");
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, "id", TARGET_TYPE, "get");
        assertThat(result, is(false));
    }

    @Test
    public void hasPermission4InvalidPermissionType() {
        final UsernamePasswordAuthenticationToken authentication = setUpTest();

        boolean result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ZERO, TARGET_TYPE, 1);
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.ONE, TARGET_TYPE, 1);
        assertThat(result, is(false));

        result = certificatePermissionEvaluator.hasPermission(authentication, BigInteger.TEN, TARGET_TYPE, 1);
        assertThat(result, is(false));
    }

    private UsernamePasswordAuthenticationToken setUpTest() {
        final UsernamePasswordAuthenticationToken authentication = setUpTestUser();
        final CertificateEntity testCertificateEntity = new CertificateEntity();
        testCertificateEntity.setUserId(TEST_USER_NAME);
        final CertificateEntity otherCertificateEntity = new CertificateEntity();
        otherCertificateEntity.setUserId(TEST_USER_NAME + "other");
        given(certificateRepositoryMock.findOneBySerial(BigInteger.ZERO)).willReturn(Optional.of
                (testCertificateEntity));
        given(certificateRepositoryMock.findOneBySerial(BigInteger.ONE)).willReturn(Optional.of
                (otherCertificateEntity));
        given(certificateRepositoryMock.findOneBySerial(BigInteger.TEN)).willReturn(Optional.empty());
        return authentication;
    }

    private UsernamePasswordAuthenticationToken setUpTestUser() {
        final User testUser = new User(TEST_USER_NAME, "", DEFAULT_USER_ROLES);
        final UsernamePasswordAuthenticationToken authentication = new
                UsernamePasswordAuthenticationToken(testUser, "", DEFAULT_USER_ROLES);

        return authentication;
    }
}