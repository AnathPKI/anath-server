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

import ch.zhaw.ba.anath.pki.core.*;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateRevocationListValidityProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SignatureNameProvider;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.CrlEntity;
import ch.zhaw.ba.anath.pki.exceptions.*;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.repositories.CrlRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * Revoke Certificates and maintain the Certificate Revocation List. Updating the Certificate Revocation List must be
 * done atomitally. Only use the locked operations {@link #cleanAndPersistLocked(CrlEntity)} and
 * {@link #getCrlEntityLocked()} to store and retrieve the CRL.
 *
 * @author Rafael Ostertag
 */
@Slf4j
@Service
@Transactional(transactionManager = "pkiTransactionManager")
public class RevocationService {
    private final CertificateAuthorityService certificateAuthorityService;
    private final CertificateRepository certificateRepository;
    private final SignatureNameProvider signatureNameProvider;
    private final CertificateRevocationListValidityProvider certificateRevocationListValidityProvider;
    private final CrlRepository crlRepository;
    private final ReentrantLock reentrantLock;
    private CertificateAuthority certificateAuthority = null;
    private CertificateRevocationListCreator certificateRevocationListCreator = null;

    public RevocationService(CertificateAuthorityService certificateAuthorityService,
                             CertificateRepository certificateRepository,
                             SignatureNameProvider signatureNameProvider,
                             CertificateRevocationListValidityProvider certificateRevocationListValidityProvider,
                             CrlRepository crlRepository) {
        this.certificateAuthorityService = certificateAuthorityService;
        this.certificateRepository = certificateRepository;
        this.signatureNameProvider = signatureNameProvider;
        this.certificateRevocationListValidityProvider = certificateRevocationListValidityProvider;
        this.crlRepository = crlRepository;

        reentrantLock = new ReentrantLock();
    }

    /**
     * Revoke the certificate with a given serial number. This will also update the Certificate Revocation List.
     *
     * @param serial serial of the certificate
     * @param reason the reason. Must not be empty or null.
     */
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

        updateCertificateRevocationList();
    }

    /**
     * Update the Revocation List with all revoked certificates. This method can be called to regenerate the
     * certificate revocation list, when it is nearing it's next update.
     */
    public void updateCertificateRevocationList() {
        initializeCertificateRevocationListCreator();
        final List<RevokedCertificate> revokedCertificates = certificateRepository
                .findAllRevoked()
                .stream()
                .map(x -> {
                    final Certificate certificate = certificateEntityToCertificate(x);
                    return new RevokedCertificate(certificate, x.getRevocationTime());
                })
                .collect(Collectors.toList());

        final CertificateRevocationList certificateRevocationList = certificateRevocationListCreator.create
                (revokedCertificates);
        log.info("Create X.509 Certificate Revocation List");
        persistCertificateRevocationList(certificateRevocationList);
    }

    public Date getNextUpdate() {
        final CrlEntity crlEntity = getCrlEntityLocked();
        return crlEntity.getNextUpdate();
    }

    public String getCrlPemEncoded() {
        final CrlEntity crlEntity = getCrlEntityLocked();
        return new String(crlEntity.getX509PEMCrl());
    }

    /**
     * Convert a {@link CertificateRevocationList} instance to an {@link CrlEntity}.
     *
     * @param certificateRevocationList {@link CertificateRevocationList} instance.
     *
     * @return {@link CrlEntity} instance.
     */
    private CrlEntity certificateRevocationListToCrlEntity(CertificateRevocationList certificateRevocationList) {
        try (ByteArrayOutputStream pemEncodedCrl = new ByteArrayOutputStream();
             OutputStreamWriter writer = new OutputStreamWriter(pemEncodedCrl)) {

            final PEMCertificateRevocationListWriter pemCertificateRevocationListWriter = new
                    PEMCertificateRevocationListWriter(writer);
            pemCertificateRevocationListWriter.writeRevocationList(certificateRevocationList);

            final CrlEntity crlEntity = new CrlEntity();
            crlEntity.setNextUpdate(new Timestamp(certificateRevocationList.getNextUpdate().getTime()));
            crlEntity.setThisUpdate(new Timestamp(certificateRevocationList.getThisUpdate().getTime()));
            crlEntity.setX509PEMCrl(pemEncodedCrl.toByteArray());

            return crlEntity;
        } catch (IOException e) {
            log.info("Error converting Certificate Revocation List to database entity: {}", e.getMessage());
            throw new RevocationListCreationException("Error converting Certificate Revocation List to database " +
                    "entity", e);
        }
    }

    /**
     * Persist the Certificate Revocation List.
     *
     * @param certificateRevocationList {@link CertificateRevocationList} instance to be persisted to the database.
     */
    private void persistCertificateRevocationList(CertificateRevocationList certificateRevocationList) {
        final CrlEntity crlEntity = certificateRevocationListToCrlEntity(certificateRevocationList);
        cleanAndPersistLocked(crlEntity);
    }

    /**
     * Clears the Certificate Revocation List table and stores a new Certificate Revocation List. It locks the
     * {@link #reentrantLock} before performing the operation.
     *
     * @param crlEntity {@link CrlEntity} crlEntity;
     */
    private void cleanAndPersistLocked(CrlEntity crlEntity) {
        try {
            log.info("Acquiring CRL lock");
            reentrantLock.lock();
            log.info("CRL lock acquired");
            // We always clean out the entire table.
            crlRepository
                    .findAllOrderByThisUpdateDesc()
                    .stream()
                    .forEach(x -> crlRepository.deleteById(x.getId()));
            log.info("Purged all previous CRLs from the database");

            crlRepository.save(crlEntity);
            log.info("Persisted X.509 Certificate Revocation List to database");
        } finally {
            log.info("Release CRL lock");
            reentrantLock.unlock();
            log.info("CRL lock released");
        }
    }

    private Certificate certificateEntityToCertificate(CertificateEntity certifcateEntity) {
        try (ByteArrayInputStream pemEncodedCertificate = new ByteArrayInputStream(certifcateEntity
                .getX509PEMCertificate());
             InputStreamReader inputStreamReader = new InputStreamReader(pemEncodedCertificate)) {
            final PEMCertificateReader pemCertificateReader = new PEMCertificateReader(inputStreamReader);
            return pemCertificateReader.certificate();
        } catch (IOException e) {
            log.error("Error reading certificate from database: {}", e.getMessage());
            throw new RevocationListCreationException("Error reading certificate", e);
        }
    }

    private void initializeCertificateRevocationListCreator() {
        if (certificateRevocationListCreator != null) {
            return;
        }

        initializeCertificateAuthority();

        certificateRevocationListCreator = new
                CertificateRevocationListCreator(signatureNameProvider, certificateAuthority,
                certificateRevocationListValidityProvider);

        log.info("Initialized and cached certificate revocation list creator");
    }

    private void initializeCertificateAuthority() {
        if (certificateAuthority != null) {
            return;
        }

        certificateAuthority = certificateAuthorityService.getCertificateAuthority();
        log.info("Loaded and cached certificate authority");
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

    private CrlEntity getCrlEntityLocked() {
        try {
            log.info("Acquire CRL lock");
            reentrantLock.lock();
            log.info("CRL lock acquired");

            final List<CrlEntity> allOrderByThisUpdateDesc = crlRepository.findAllOrderByThisUpdateDesc();
            final Optional<CrlEntity> firstCrlEntity = allOrderByThisUpdateDesc.stream().findFirst();
            return firstCrlEntity.orElseThrow(() -> {
                log.error("No Certificate Revocation List found. CA not initialized?");
                return new CertificateAuthorityNotInitializedException("No Certificate Revocation List found");
            });
        } finally {
            log.info("Release CRL lock");
            reentrantLock.unlock();
            log.info("CRL lock released");
        }
    }
}