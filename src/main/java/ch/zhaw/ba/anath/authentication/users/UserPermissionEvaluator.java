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

package ch.zhaw.ba.anath.authentication.users;

import ch.zhaw.ba.anath.authentication.AnathSecurityHelper;
import ch.zhaw.ba.anath.users.entities.UserEntity;
import ch.zhaw.ba.anath.users.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * @author Rafael Ostertag
 */
@Component
@Transactional(transactionManager = "userTransactionManager")
@Slf4j
public class UserPermissionEvaluator implements PermissionEvaluator {
    private final UserRepository userRepository;
    private final Set<String> userPermissions;

    public UserPermissionEvaluator(UserRepository userRepository) {
        this.userRepository = userRepository;

        userPermissions = new HashSet<>();
        userPermissions.add("changePassword");
        userPermissions.add("get");
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        throw new UnsupportedOperationException("hasPermission(Authentication,Object,Object) unsupported");
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object
            permission) {
        if (targetType.equals("user")) {
            log.info("Start evaluating permission for user object");
            return handleUserObject(authentication, targetId, permission);
        }
        log.info("Unknown target received: {}. Denying", targetType);
        return false;
    }

    private boolean handleUserObject(Authentication authentication, Serializable targetId, Object permission) {
        if (!(targetId instanceof Long)) {
            log.error("Cannot evaluate permission for user object, target id is not of type Long. Denying");
            return false;
        }
        if (!(permission instanceof String)) {
            log.error("Cannot evaluate permission for user object, permission is not of type String. Denying");
            return false;
        }

        Long realId = (Long) targetId;
        String realPermission = (String) permission;

        if (!userPermissions.contains(realPermission)) {
            log.info("User permission '{}' unknown. Denying", realPermission);
            return false;
        }

        final Optional<UserEntity> optionalUserEntity = userRepository.findOne(realId);
        if (!optionalUserEntity.isPresent()) {
            log.info("Cannot evaluate permission for non-existing user with id {}. Denying", realId);
            return false;
        }

        final UserEntity userEntity = optionalUserEntity.get();
        final String username = AnathSecurityHelper.getUsername(authentication);

        boolean result = userEntity.getEmail().equals(username);
        log.info("User '{}' has {} to user object '{}'. {}", username, result ? "access" : "no access", userEntity
                .getEmail(), result ? "Allowing" : "Denying");
        return result;
    }
}
