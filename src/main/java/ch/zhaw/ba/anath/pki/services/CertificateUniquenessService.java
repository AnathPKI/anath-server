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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyExistsException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service testing a given {@link CertificateEntity} for uniqueness in database.
 *
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class CertificateUniquenessService {
    private final CertificateRepository certificateRepository;

    public CertificateUniquenessService(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    /**
     * Uniqueness test. A certificate is unique if no other non-expired, non-revoked certificate with the same
     * subject exists in the certificate repository.
     *
     * @param certificateSubject certificate subject as string.
     *
     * @throws CertificateAlreadyExistsException when another non-expired, non-revoked certificate with the same
     *                                           subject has been found
     */
    public void testCertificateUniquenessInCertificateRepositoryOrThrow(String certificateSubject) {
        final List<CertificateEntity> allBySubject = certificateRepository.findAllBySubject(certificateSubject);
        if (allBySubject.isEmpty()) {
            return;
        }

        final boolean hasValidCertificate = allBySubject.stream().anyMatch(CertificateValidityUtils::isValid);
        if (hasValidCertificate) {
            // Since we found a certificate with the given subject which is valid, this certificate is not considered
            // to be unique.

            log.error("There is already a valid certificate with subject '{}'", certificateSubject);
            throw new CertificateAlreadyExistsException(String.format("Valid certificate for '%s' already exists",
                    certificateSubject));
        }
    }
}
