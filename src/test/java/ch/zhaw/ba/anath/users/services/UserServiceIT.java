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

package ch.zhaw.ba.anath.users.services;

import ch.zhaw.ba.anath.users.dto.*;
import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.exceptions.PasswordMismatchException;
import ch.zhaw.ba.anath.users.exceptions.UserDoesNotExistException;
import ch.zhaw.ba.anath.users.exceptions.UserPasswordException;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@ActiveProfiles("tests")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Transactional(transactionManager = "userTransactionManager")
public class UserServiceIT {
    private static final String EMAIL = "email";
    private static final String FIRSTNAME = "firstname";
    private static final String LASTNAME = "lastname";
    private static final String PASSWORD = "password";
    @PersistenceContext(unitName = "users")
    private EntityManager entityManager;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void createUser() {
        final CreateUserDto createUserDto = makeCreateUserDto();

        final UserLinkDto user = userService.createUser(createUserDto);
        flushAndClear();

        final Optional<UserEntity> optionalUserEntity = userRepository.findOneByEmail(EMAIL);
        assertThat(optionalUserEntity.isPresent(), is(true));

        final UserEntity userEntity = optionalUserEntity.get();

        assertThat(user.getUserId(), is(userEntity.getId()));
        assertThat(user.getEmail(), is(EMAIL));
        assertThat(userEntity.getPassword(), is(not(equalTo(PASSWORD))));
        assertThat(userEntity.getPassword(), startsWith("$"));

        assertThat(passwordEncoder.matches(PASSWORD, userEntity.getPassword()), is(true));
    }

    private CreateUserDto makeCreateUserDto() {
        final CreateUserDto createUserDto = new CreateUserDto();
        createUserDto.setPassword(PASSWORD);
        createUserDto.setLastname(LASTNAME);
        createUserDto.setFirstname(FIRSTNAME);
        createUserDto.setEmail(EMAIL);
        createUserDto.setAdmin(false);
        return createUserDto;
    }

    @Test(expected = UserPasswordException.class)
    public void createUserWithNullPassword() {
        final CreateUserDto createUserDto = makeCreateUserDto();
        createUserDto.setPassword(null);
        userService.createUser(createUserDto);
    }

    @Test(expected = UserPasswordException.class)
    public void createUserWithEmptyPassword() {
        final CreateUserDto createUserDto = makeCreateUserDto();
        createUserDto.setPassword("");
        userService.createUser(createUserDto);
    }

    @Test(expected = UserDoesNotExistException.class)
    public void deleteNonExistingUser() {
        userService.deleteUser(1L);
    }

    @Test
    public void deleteUser() {
        final CreateUserDto createUserDto = makeCreateUserDto();
        final UserLinkDto user = userService.createUser(createUserDto);

        userService.deleteUser(user.getUserId());
        flushAndClear();

        final UserEntity userEntity = entityManager.find(UserEntity.class, user.getUserId());
        assertThat(userEntity, is(nullValue()));
    }

    @Test
    public void updateUser() {
        final UserEntity userEntity = makeUserEntity();

        userRepository.save(userEntity);
        flushAndClear();

        final UpdateUserDto updateUserDto = new UpdateUserDto();
        updateUserDto.setAdmin(false);
        updateUserDto.setLastname("another " + LASTNAME);
        updateUserDto.setFirstname("another " + FIRSTNAME);

        final UserLinkDto userLinkDto = userService.updateUser(userEntity.getId(), updateUserDto);
        assertThat(userLinkDto.getEmail(), is(EMAIL));
        assertThat(userLinkDto.getUserId(), is(userEntity.getId()));
        flushAndClear();

        final Optional<UserEntity> optionalUserEntity = userRepository.findOne(userEntity.getId());
        final UserEntity actual = optionalUserEntity.get();
        assertThat(actual.getPassword(), is(PASSWORD));
        assertThat(actual.getLastname(), is("another " + LASTNAME));
        assertThat(actual.getFirstname(), is("another " + FIRSTNAME));
        assertThat(actual.getEmail(), is(EMAIL));
        assertThat(actual.getAdmin(), is(false));
    }

    private UserEntity makeUserEntity() {
        final UserEntity userEntity = new UserEntity();
        userEntity.setEmail(EMAIL);
        userEntity.setPassword(PASSWORD);
        userEntity.setLastname(LASTNAME);
        userEntity.setFirstname(FIRSTNAME);
        userEntity.setAdmin(true);
        return userEntity;
    }

    @Test(expected = UserDoesNotExistException.class)
    public void updateNonExistingUser() {
        userService.updateUser(42L, new UpdateUserDto());
    }

    @Test
    public void changePassword() {
        final CreateUserDto createUserDto = makeCreateUserDto();
        final UserLinkDto user = userService.createUser(createUserDto);
        flushAndClear();

        final ChangePasswordDto changePasswordDto = new ChangePasswordDto();
        changePasswordDto.setNewPassword(PASSWORD + PASSWORD);
        changePasswordDto.setOldPassword(PASSWORD);

        final UserLinkDto userLinkDto = userService.changePassword(user.getUserId(), changePasswordDto);
        flushAndClear();
        assertThat(userLinkDto, is(equalTo(user)));

        final Optional<UserEntity> optionalUserEntity = userRepository.findOne(user.getUserId());
        final UserEntity userEntity = optionalUserEntity.get();
        assertThat(passwordEncoder.matches(PASSWORD + PASSWORD, userEntity.getPassword()), is(true));
    }

    private void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }

    @Test(expected = UserDoesNotExistException.class)
    public void changePasswordNonExistingUser() {
        userService.changePassword(42L, new ChangePasswordDto());
    }

    @Test(expected = PasswordMismatchException.class)
    public void changePasswordWithNonMatchingOldPassword() {
        final CreateUserDto createUserDto = makeCreateUserDto();
        final UserLinkDto user = userService.createUser(createUserDto);
        flushAndClear();

        final ChangePasswordDto changePasswordDto = new ChangePasswordDto();
        changePasswordDto.setNewPassword(PASSWORD + PASSWORD);
        changePasswordDto.setOldPassword("does not match");

        userService.changePassword(user.getUserId(), changePasswordDto);
    }

    @Test
    public void getUser() {
        final UserEntity userEntity = makeUserEntity();
        userRepository.save(userEntity);
        flushAndClear();

        final UserDto user = userService.getUser(userEntity.getId());

        assertThat(user.getEmail(), is(userEntity.getEmail()));
        assertThat(user.getFirstname(), is(userEntity.getFirstname()));
        assertThat(user.getLastname(), is(userEntity.getLastname()));
        assertThat(user.isAdmin(), is(userEntity.getAdmin()));
    }

    @Test(expected = UserDoesNotExistException.class)
    public void getNonExistingUser() {
        userService.getUser(42L);
    }

    @Test
    public void getAllEmpty() {
        final List<UserLinkDto> all = userService.getAll();
        assertThat(all, hasSize(0));
    }

    @Test
    public void getAll() {
        final UserEntity userEntity1 = makeUserEntity();
        userRepository.save(userEntity1);

        final UserEntity userEntity2 = makeUserEntity();
        userEntity2.setEmail("email2");
        userRepository.save(userEntity2);

        final List<UserLinkDto> all = userService.getAll();
        assertThat(all, hasSize(2));
    }
}