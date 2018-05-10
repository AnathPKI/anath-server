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

package ch.zhaw.ba.anath.users;

import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.junit.Before;
import org.junit.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;

/**
 * @author Rafael Ostertag
 */
public class InitialAdministratorCreatorTest {
    private static final String TEST_APPLICATION_ID = "theid";
    private ApplicationContext applicationContextMock;
    private UserRepository userRepositoryMock;
    private PasswordEncoder passwordEncoderMock;
    private InitialAdministratorCreator initialAdministratorCreator;

    @Before
    public void setUp() {
        this.applicationContextMock = mock(ApplicationContext.class);
        this.userRepositoryMock = mock(UserRepository.class);
        this.passwordEncoderMock = mock(PasswordEncoder.class);
        this.initialAdministratorCreator = new InitialAdministratorCreator(userRepositoryMock,
                applicationContextMock, passwordEncoderMock);
    }

    @Test
    public void noPreviousAdministrator() {
        given(applicationContextMock.getId()).willReturn(TEST_APPLICATION_ID);
        given(userRepositoryMock.findAllByAdmin(true)).willReturn(Collections.emptyList());
        given(passwordEncoderMock.encode(anyString())).willReturn("encoded_password");

        UserEntity expectedUserEntity = makeExpectedUserEntity();
        expectedUserEntity.setPassword("encoded_password");

        initialAdministratorCreator.processApplicationPreparedEvent(makeApplicationReadyEvent());

        then(userRepositoryMock).should().save(expectedUserEntity);
    }

    @Test
    public void withPreviousAdministrator() {
        given(applicationContextMock.getId()).willReturn(TEST_APPLICATION_ID);
        given(userRepositoryMock.findAllByAdmin(true)).willReturn(Collections.singletonList(makeExpectedUserEntity()));
        given(passwordEncoderMock.encode(anyString())).willReturn("encoded_password");

        initialAdministratorCreator.processApplicationPreparedEvent(makeApplicationReadyEvent());

        then(userRepositoryMock).should(never()).save(any());
    }

    @Test
    public void nonMatchingApplicationId() {
        given(applicationContextMock.getId()).willReturn("another_id");

        initialAdministratorCreator.processApplicationPreparedEvent(makeApplicationReadyEvent());

        then(userRepositoryMock).should(never()).findAllByAdmin(anyBoolean());
        then(userRepositoryMock).should(never()).save(any());
    }

    private ApplicationReadyEvent makeApplicationReadyEvent() {
        final ConfigurableApplicationContext configurableApplicationContextMock = mock(ConfigurableApplicationContext
                .class);
        given(configurableApplicationContextMock.getId()).willReturn(TEST_APPLICATION_ID);

        return new ApplicationReadyEvent(mock(SpringApplication.class),
                new String[]{},
                configurableApplicationContextMock);
    }

    private UserEntity makeExpectedUserEntity() {
        final UserEntity userEntity = new UserEntity();
        userEntity.setEmail(InitialAdministratorCreator.INITIAL_USER_USERNAME);
        userEntity.setFirstname(InitialAdministratorCreator.INITIAL_USER_FIRSTNAME);
        userEntity.setLastname(InitialAdministratorCreator.INITIAL_USER_LASTNAME);
        userEntity.setAdmin(true);
        return userEntity;
    }
}