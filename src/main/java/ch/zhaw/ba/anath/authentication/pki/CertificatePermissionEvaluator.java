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

import ch.zhaw.ba.anath.authentication.AnathSecurityHelper;
import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * @author Rafael Ostertag
 */
@Component
@Transactional(transactionManager = "pkiTransactionManager")
@Slf4j
public class CertificatePermissionEvaluator implements PermissionEvaluator {
    public static final String TARGET_TYPE = "certificate";
    public static final String PERMISSION_NOT_STRING_MESSAGE = "Cannot evaluate permission for certificate object, " +
            "permission is not of type String. Denying";

    public static final String CERTIFICATE_PERMISSION_UNKNOWN_MESSAGE = "Certificate permission '{}' unknown. Denying";

    private final CertificateRepository certificateRepository;
    private final Set<String> certificatePermissions;

    public CertificatePermissionEvaluator(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;

        certificatePermissions = new HashSet<>();
        certificatePermissions.add("get");
        certificatePermissions.add("revoke");
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (!(targetDomainObject instanceof CertificateListItemDto)) {
            log.info("Unknown targetDomainObject received: {}. Denying.", targetDomainObject.getClass().getName());
            return false;
        }

        if (!(permission instanceof String)) {
            log.error(PERMISSION_NOT_STRING_MESSAGE);
            return false;
        }

        String realPermission = (String) permission;

        if (!certificatePermissions.contains(realPermission)) {
            log.info(CERTIFICATE_PERMISSION_UNKNOWN_MESSAGE, realPermission);
            return false;
        }

        final CertificateListItemDto realObject = (CertificateListItemDto) targetDomainObject;
        if (realObject.getUserId() == null) {
            log.error("userId is null. Denying.");
            return false;
        }
        final String username = AnathSecurityHelper.getUsername(authentication);

        return realObject.getUserId().equals(username);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object
            permission) {
        if (targetType.equals(TARGET_TYPE)) {
            log.info("Start evaluating permission for certificate object");
            return handleCertificateObject(authentication, targetId, permission);
        }
        log.info("Unknown target received: {}. Denying", targetType);
        return false;
    }

    private boolean handleCertificateObject(Authentication authentication, Serializable targetId, Object permission) {
        if (!(targetId instanceof BigInteger)) {
            log.error("Cannot evaluate permission for certificate object, target id is not of type BigInteger. " +
                    "Denying");
            return false;
        }
        if (!(permission instanceof String)) {
            log.error(PERMISSION_NOT_STRING_MESSAGE);
            return false;
        }

        BigInteger realId = (BigInteger) targetId;
        String realPermission = (String) permission;

        if (!certificatePermissions.contains(realPermission)) {
            log.info(CERTIFICATE_PERMISSION_UNKNOWN_MESSAGE, realPermission);
            return false;
        }

        final Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(realId);
        if (!optionalCertificateEntity.isPresent()) {
            log.info("Cannot evaluate permission for non-existing certificate with id {}. Denying", realId.toString());
            return false;
        }

        final CertificateEntity certificateEntity = optionalCertificateEntity.get();
        final String username = AnathSecurityHelper.getUsername(authentication);

        boolean result = certificateEntity.getUserId().equals(username);
        log.info("User '{}' has {} to certificate object '{}'. {}", username, result ? "access" : "no access",
                certificateEntity
                        .getUserId(), result ? "Allowing" : "Denying");
        return result;
    }
}
