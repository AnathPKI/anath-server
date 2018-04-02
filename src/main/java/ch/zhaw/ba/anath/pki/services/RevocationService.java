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
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyRevokedException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.exceptions.RevocationNoReasonException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Optional;

/**
 * @author Rafael Ostertag
 */
@Slf4j
@Service
@Transactional(transactionManager = "pkiTransactionManager")
public class RevocationService {

    private CertificateRepository certificateRepository;

    public RevocationService(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    public void revokeCertificate(BigInteger serial, String reason) {

        if (reason == null) {
            throwEmptyReasonException(serial);
            return;
        }

        String trimmedReason = reason.trim();
        if (trimmedReason.isEmpty()) {
            throwEmptyReasonException(serial);
            return;
        }

        final CertificateEntity certificateEntity = getCertificateEntityOrThrow(serial);

        if (certificateEntity.getStatus() == CertificateStatus.REVOKED) {
            log.error("Cannot revoke already revoked certificate with serial {}", serial);
            throw new CertificateAlreadyRevokedException("Certificate already revoked");
        }

        certificateEntity.setRevocationReason(trimmedReason);
        certificateEntity.setStatus(CertificateStatus.REVOKED);
        certificateEntity.setRevocationTime(new Timestamp(System.currentTimeMillis()));

        certificateRepository.save(certificateEntity);
        log.info("Revoked certificate with serial {} with reason '{}'", serial.toString(), trimmedReason);
    }

    private void throwEmptyReasonException(BigInteger serial) {
        log.error("Cannot revoke certificate with serial {}. No reason provided", serial);
        throw new RevocationNoReasonException("No reason provided");
    }

    private CertificateEntity getCertificateEntityOrThrow(BigInteger serial) {
        final Optional<CertificateEntity> certificateEntityOptional = certificateRepository.findOneBySerial(serial);
        return certificateEntityOptional.orElseThrow(() -> {
            log.error("Certificate with serial {} not found", serial.toString());
            return new CertificateNotFoundException("Certificate not found");
        });
    }
}
