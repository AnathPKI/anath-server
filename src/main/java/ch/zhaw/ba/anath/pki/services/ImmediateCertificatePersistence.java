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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyExistsException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.ConstraintViolationException;
import java.math.BigInteger;
import java.util.Optional;

/**
 * @author Rafael Ostertag
 */
@Service
@Profile("!confirm")
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class ImmediateCertificatePersistence implements ConfirmableCertificatePersistenceLayer {
    private final CertificateRepository certificateRepository;

    public ImmediateCertificatePersistence(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
        log.info("Immediate Certificate Persistence Layer initialized");
    }

    @Override
    public String store(CertificateEntity certificateEntity) {
        try {
            certificateRepository.save(certificateEntity);
            log.info("Stored signed certificate '{}'", certificateEntity.getSubject());
            return certificateEntity.getSerial().toString();
        } catch (ConstraintViolationException e) {
            final String subjectString = certificateEntity.getSubject();
            log.error("Error persisting certificate '{}' with serial '{}': {}", subjectString,
                    certificateEntity.getSerial().toString(), e.getMessage());
            throw new CertificateAlreadyExistsException(String.format("Certificate already exists: %s", subjectString));
        }
    }

    @Override
    public CertificateEntity confirm(String token, String userId) {
        BigInteger serial;
        try {
            serial = new BigInteger(token);
        } catch (NumberFormatException e) {
            log.error("Cannot parse '{}' as BigInteger: {}", token, e.getMessage());
            throw new CertificateNotFoundException("Certificate not found");
        }

        final Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(serial);
        return optionalCertificateEntity.orElseThrow(() -> {
            log.error("Cannot find certificate with serial {}", serial.toString());
            return new CertificateNotFoundException("Certificate not found");
        });
    }
}
