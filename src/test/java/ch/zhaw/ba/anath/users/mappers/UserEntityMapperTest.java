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

package ch.zhaw.ba.anath.users.mappers;

import ch.zhaw.ba.anath.users.dto.CreateUserDto;
import ch.zhaw.ba.anath.users.dto.UpdateUserDto;
import ch.zhaw.ba.anath.users.dto.UserDto;
import ch.zhaw.ba.anath.users.dto.UserLinkDto;
import ch.zhaw.ba.anath.users.entities.UserEntity;
import fr.xebia.extras.selma.Selma;
import org.junit.Test;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
public class UserEntityMapperTest {
    private final static UserEntityMapper MAPPER = Selma.builder(UserEntityMapper.class).build();
    private static final String LASTNAME = "lastname";
    private static final String FIRSTNAME = "firstname";
    private static final String PASSWORD = "password";
    private static final String EMAIL = "email";
    private static final long ID = 42L;
    private static final boolean ADMIN = true;

    @Test
    public void asUserLinkDto() {
        final UserEntity userEntity = new UserEntity();
        userEntity.setId(ID);

        final UserLinkDto userLinkDto = MAPPER.asUserLinkDto(userEntity);
        assertThat(userLinkDto.getUserId(), is(ID));
    }

    @Test
    public void asEntity() {
        final CreateUserDto createUserDto = new CreateUserDto();
        createUserDto.setAdmin(ADMIN);
        createUserDto.setEmail(EMAIL);
        createUserDto.setFirstname(FIRSTNAME);
        createUserDto.setLastname(LASTNAME);
        createUserDto.setPassword(PASSWORD);

        final UserEntity actual = MAPPER.asEntity(createUserDto);
        assertThat(actual.getId(), is(nullValue()));
        assertThat(actual.getLastname(), is(LASTNAME));
        assertThat(actual.getFirstname(), is(FIRSTNAME));
        assertThat(actual.getPassword(), is(PASSWORD));
        assertThat(actual.getEmail(), is(EMAIL));
        assertThat(actual.getAdmin(), is(ADMIN));
    }

    @Test
    public void updateEntity() {
        final UserEntity userEntity = makeTestEntity();

        final UpdateUserDto updateUserDto = new UpdateUserDto();
        updateUserDto.setFirstname("another " + FIRSTNAME);
        updateUserDto.setLastname("another " + LASTNAME);

        final UserEntity actual = MAPPER.updateEntity(updateUserDto, userEntity);
        assertThat(actual, is(sameInstance(userEntity)));

        assertThat(actual.getId(), is(ID));
        assertThat(actual.getAdmin(), is(ADMIN));
        assertThat(actual.getEmail(), is(EMAIL));
        assertThat(actual.getPassword(), is(PASSWORD));
        assertThat(actual.getFirstname(), is("another " + FIRSTNAME));
        assertThat(actual.getLastname(), is("another " + LASTNAME));
    }

    private UserEntity makeTestEntity() {
        final UserEntity userEntity = new UserEntity();
        userEntity.setId(ID);
        userEntity.setEmail(EMAIL);
        userEntity.setAdmin(ADMIN);
        userEntity.setPassword(PASSWORD);
        userEntity.setFirstname(FIRSTNAME);
        userEntity.setLastname(LASTNAME);
        return userEntity;
    }

    @Test
    public void asUserDto() {
        final UserEntity userEntity = makeTestEntity();

        final UserDto actual = MAPPER.asUserDto(userEntity);

        assertThat(actual.getId(), is(nullValue()));
        assertThat(actual.getLastname(), is(LASTNAME));
        assertThat(actual.getFirstname(), is(FIRSTNAME));
        assertThat(actual.getEmail(), is(EMAIL));
        assertThat(actual.isAdmin(), is(ADMIN));
    }
}