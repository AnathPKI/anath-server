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

package ch.zhaw.ba.anath.users.services;

import ch.zhaw.ba.anath.users.dto.*;
import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.exceptions.PasswordMismatchException;
import ch.zhaw.ba.anath.users.exceptions.UserDoesNotExistException;
import ch.zhaw.ba.anath.users.exceptions.UserPasswordException;
import ch.zhaw.ba.anath.users.mappers.UserEntityMapper;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "userTransactionManager")
public class UserService {
    private final UserRepository userRepository;
    private final UserEntityMapper userEntityMapper;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, UserEntityMapper userEntityMapper, PasswordEncoder
            passwordEncoder) {
        this.userRepository = userRepository;
        this.userEntityMapper = userEntityMapper;
        this.passwordEncoder = passwordEncoder;
    }

    public UserLinkDto createUser(CreateUserDto createUserDto) {
        log.info("Create new user '{}'", createUserDto.getEmail());
        final UserEntity newUserEntity = userEntityMapper.asEntity(createUserDto);

        if (newUserEntity.getPassword() == null || newUserEntity.getPassword().isEmpty()) {
            log.error("User '{}' must not have empty password", newUserEntity.getEmail());
            throw new UserPasswordException("User must not have empty password");
        }

        log.info("Encoding password for new user '{}'", newUserEntity.getEmail());
        newUserEntity.setPassword(passwordEncoder.encode(newUserEntity.getPassword()));

        log.info("Saving new user '{}'", newUserEntity.getEmail());
        userRepository.save(newUserEntity);

        return userEntityMapper.asUserLinkDto(newUserEntity);
    }

    public void deleteUser(long id) {
        final UserEntity userEntity = findUserEntityByIdOrThrow(id);

        log.info("Delete user '{}' with id '{}'", userEntity.getEmail(), id);
        userRepository.deleteById(id);
    }

    private UserEntity findUserEntityByIdOrThrow(long id) {
        final Optional<UserEntity> optionalUserEntity = userRepository.findOne(id);
        return optionalUserEntity.orElseThrow(() -> {
            log.error("Unable to find user with id '{}'", id);
            return new UserDoesNotExistException("Unable to find user");
        });
    }

    public UserLinkDto updateUser(long id, UpdateUserDto updateUserDto) {
        final UserEntity userEntity = findUserEntityByIdOrThrow(id);
        log.info("Update user '{}' with id '{}'", userEntity.getEmail(), id);

        userEntityMapper.updateEntity(updateUserDto, userEntity);

        userRepository.save(userEntity);

        return userEntityMapper.asUserLinkDto(userEntity);
    }

    public UserLinkDto changePassword(long id, ChangePasswordDto changePasswordDto) {
        final UserEntity userEntity = findUserEntityByIdOrThrow(id);

        log.info("Updating password of user '{}' with id '{}'", userEntity.getEmail(), id);
        if (!passwordEncoder.matches(changePasswordDto.getOldPassword(), userEntity.getPassword())) {
            log.info("Cannot updated password of user '{}'. Old password incorrect", userEntity.getEmail());
            throw new PasswordMismatchException("Old password incorrect");
        }

        userEntity.setPassword(passwordEncoder.encode(changePasswordDto.getNewPassword()));

        return userEntityMapper.asUserLinkDto(userEntity);
    }

    public UserDto getUser(long id) {
        log.info("Looking up user with id '{}'", id);

        final Optional<UserEntity> userEntityOptional = userRepository.findOne(id);
        final UserEntity userEntity = userEntityOptional.orElseThrow(() -> {
            log.error("User with id '{}' not found", id);
            return new UserDoesNotExistException("User not found");
        });

        return userEntityMapper.asUserDto(userEntity);
    }

    public UserDto getUser(String emailAdress) {
        log.info("Looking up user with email address '{}'", emailAdress);

        final Optional<UserEntity> userEntityOptional = userRepository.findOneByEmail(emailAdress);
        final UserEntity userEntity = userEntityOptional.orElseThrow(() -> {
            log.error("User with email address '{}' not found", emailAdress);
            return new UserDoesNotExistException("User not found");
        });

        return userEntityMapper.asUserDto(userEntity);
    }

    public List<UserLinkDto> getAll() {
        return userRepository.findAll().stream()
                .map(userEntityMapper::asUserLinkDto)
                .collect(Collectors.toList());
    }
}
