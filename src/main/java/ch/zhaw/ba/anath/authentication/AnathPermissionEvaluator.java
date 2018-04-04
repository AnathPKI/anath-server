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

package ch.zhaw.ba.anath.authentication;

import ch.zhaw.ba.anath.authentication.pki.CertificatePermissionEvaluator;
import ch.zhaw.ba.anath.authentication.users.UserPermissionEvaluator;
import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.HashMap;

/**
 * @author Rafael Ostertag
 */
@Component
@Slf4j
public class AnathPermissionEvaluator implements PermissionEvaluator {
    public static final String DEFAULT_DENY_PERMISSION_HANDLER_CALLED_MESSAGE = "Default deny permission handler " +
            "called";

    private final HashMap<String, PermissionEvaluator> permissionEvaluatorsByTargetType;
    private final PermissionEvaluator defaultDenyEvaluator;

    public AnathPermissionEvaluator(UserPermissionEvaluator userPermissionEvaluator, CertificatePermissionEvaluator
            certificatePermissionEvaluator) {
        this.permissionEvaluatorsByTargetType = new HashMap<>();
        permissionEvaluatorsByTargetType.put(UserPermissionEvaluator.TARGET_TYPE, userPermissionEvaluator);
        permissionEvaluatorsByTargetType.put(CertificatePermissionEvaluator.TARGET_TYPE,
                certificatePermissionEvaluator);

        this.defaultDenyEvaluator = new PermissionEvaluator() {
            @Override
            public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
                log.info(DEFAULT_DENY_PERMISSION_HANDLER_CALLED_MESSAGE);
                return false;
            }

            @Override
            public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
                                         Object permission) {
                log.info(DEFAULT_DENY_PERMISSION_HANDLER_CALLED_MESSAGE);
                return false;
            }
        };
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (targetDomainObject instanceof CertificateListItemDto) {
            final PermissionEvaluator permissionEvaluator =
                    permissionEvaluatorsByTargetType.get(CertificatePermissionEvaluator.TARGET_TYPE);
            return permissionEvaluator.hasPermission(authentication, targetDomainObject, permission);
        }

        log.error("hasPermission(Authentication,Object,Object) not supported for {}", targetDomainObject.getClass()
                .getName());
        throw new UnsupportedOperationException("hasPermission(Authentication,Object,Object) not supported");
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object
            permission) {
        final PermissionEvaluator permissionEvaluator = permissionEvaluatorsByTargetType.getOrDefault(targetType,
                defaultDenyEvaluator);
        return permissionEvaluator.hasPermission(authentication, targetId, targetType, permission);
    }
}
