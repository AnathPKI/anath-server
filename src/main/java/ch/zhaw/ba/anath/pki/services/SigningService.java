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
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateConstraintProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateSerialProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateValidityProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SignatureNameProvider;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyExistsException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
import ch.zhaw.ba.anath.pki.exceptions.SigningServiceException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.repositories.UseRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.ConstraintViolationException;
import java.io.*;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Sign a CSR and store the certificate.
 *
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class SigningService {
    private final SecureStoreService secureStoreService;
    private final CertificateRepository certificateRepository;
    private final UseRepository useRepository;
    private final CertificateConstraintProvider certificateConstraintProvider;
    private final SignatureNameProvider signatureNameProvider;
    private final CertificateValidityProvider certificateValidityProvider;
    private final CertificateSerialProvider certificateSerialProvider;
    private CertificateAuthority certificateAuthority = null;
    private CertificateSigner certificateSigner = null;

    public SigningService(SecureStoreService secureStoreService, CertificateRepository certificateRepository,
                          UseRepository useRepository, CertificateConstraintProvider certificateConstraintProvider,
                          SignatureNameProvider signatureNameProvider, CertificateValidityProvider
                                  certificateValidityProvider, CertificateSerialProvider certificateSerialProvider) {
        this.secureStoreService = secureStoreService;
        this.certificateRepository = certificateRepository;
        this.useRepository = useRepository;
        this.certificateConstraintProvider = certificateConstraintProvider;
        this.signatureNameProvider = signatureNameProvider;
        this.certificateValidityProvider = certificateValidityProvider;
        this.certificateSerialProvider = certificateSerialProvider;
    }

    /**
     * Initializes the {@link CertificateSigner} instance. It first initializes the {@link CertificateAuthority}.
     * It can be called multiple times. Once the {@link CertificateSigner} has been initialized, it won't be
     * initialized again.
     */
    private void initializeCertificateSigner() {
        if (certificateSigner != null) {
            return;
        }
        initializeCertificateAuthority();

        certificateSigner = new CertificateSigner(signatureNameProvider, certificateAuthority);
        certificateSigner.setCertificateConstraintProvider(certificateConstraintProvider);
        certificateSigner.setCertificateSerialProvider(certificateSerialProvider);
        certificateSigner.setValidityProvider(certificateValidityProvider);
    }

    /**
     * Initialize the CertificateAuthority. It can be called multiple times. Once the {@link CertificateAuthority}
     * has been initialized, it won't be initialized again.
     */
    private void initializeCertificateAuthority() {
        if (certificateAuthority != null) {
            return;
        }
        log.info("Initializing certificate authority");
        Byte[] pemCaCertificateObject = retrieveCaCertificateFromSecureStoreOrThrow();
        Byte[] pemCaPrivateKeyObject = retrieveCaPrivateKeyFromSecureStoreOrThrow();

        final ByteArrayInputStream pemCaCertificateInputStream = pemByteArrayObjectToByteArrayInputStream
                (pemCaCertificateObject);
        final ByteArrayInputStream pemCaPrivateKeyInputStream = pemByteArrayObjectToByteArrayInputStream
                (pemCaPrivateKeyObject);

        final PEMCertificateAuthorityReader pemCertificateAuthorityReader = new PEMCertificateAuthorityReader(
                new InputStreamReader(pemCaPrivateKeyInputStream),
                new InputStreamReader(pemCaCertificateInputStream)
        );

        log.info("Initialized certificate authority");
        certificateAuthority = pemCertificateAuthorityReader.certificateAuthority();
    }

    private ByteArrayInputStream pemByteArrayObjectToByteArrayInputStream(Byte[] pemObject) {
        return new ByteArrayInputStream(ArrayUtils.toPrimitive(pemObject));
    }

    private Byte[] retrieveCaPrivateKeyFromSecureStoreOrThrow() {
        final Optional<Byte[]> caPrivateKeyOptional = secureStoreService.get(CertificateAuthorityService
                .SECURE_STORE_CA_PRIVATE_KEY);
        return caPrivateKeyOptional.orElseThrow(() -> {
            log.error("Unable to retrieve certificate authority private key from secure storage");
            return new CertificateAuthorityNotInitializedException("No CA private key found");
        });
    }

    private Byte[] retrieveCaCertificateFromSecureStoreOrThrow() {
        final Optional<Byte[]> caCertificateOptional = secureStoreService.get(CertificateAuthorityService
                .SECURE_STORE_CA_CERTIFICATE);
        return caCertificateOptional.orElseThrow(() -> {
            log.error("Unable to retrieve certificate authority certificate from secure storage");
            return new CertificateAuthorityNotInitializedException("No CA certificate found");
        });
    }

    /**
     * Sign a CSR.
     * <p>
     * The CSR will be signed and added to the database. If the subject of the CSR already exists and the certificate
     * is non-revoked and non-expired, the signing process will be aborted and an exception thrown.
     * <p>
     * Besides exception mentioned below,  {@link ch.zhaw.ba.anath.pki.core.exceptions.PKIException} may be thrown.
     *
     * @param certificateSigningRequest the {@link Reader} providing the CSR.
     * @param userId                          the user id of the user the certificate belongs to.
     * @param use                             the use. If the use cannot be found in the database, the {@value
     *                                        UseEntity#DEFAULT_USE} is used.
     *
     * @throws CertificateAlreadyExistsException when a non-revoked, non-expired for the given subject already
     *                                           exists, or the serial number is taken.
     * @throws SigningServiceException           if no default certificate use can be found.
     */

    public Certificate signCertificate(CertificateSigningRequest certificateSigningRequest,
                                       String userId, String use) {
        initializeCertificateSigner();

        log.info("Sign certificate signing request");
        final Certificate certificate = certificateSigner.signCertificate(certificateSigningRequest);

        log.info("Test uniqueness of certificate");
        testCertificateUniquenessInCertificateRepositoryOrThrow(certificate);

        log.info("Signed certificate '{}'", certificate.getSubject().toString());

        log.info("Store signed certificate");
        storeCertificate(certificate, userId, use);

        return certificate;
    }

    private void testCertificateUniquenessInCertificateRepositoryOrThrow(Certificate certificate) {
        final List<CertificateEntity> allBySubject = certificateRepository.findAllBySubject(certificate.getSubject()
                .toString());
        if (allBySubject.isEmpty()) {
            return;
        }

        final boolean hasValidCertificate = allBySubject.stream().anyMatch(this::isCertificateValid);
        if (hasValidCertificate) {
            // Since we found a certificate with the given subject which is valid, this certificate is not considered
            // to be unique.

            final String subjectString = certificate.getSubject().toString();
            log.error("There is already a valid certificate with subject '{}'", subjectString);
            throw new CertificateAlreadyExistsException(String.format("Valid certificate for '%s' already exists",
                    subjectString));
        }
    }

    private boolean isCertificateValid(CertificateEntity certificateEntity) {
        final Timestamp timestampNow = new Timestamp(System.currentTimeMillis());

        // We use compareTo for the not valid before/after, since the certificate is valid if notValidBefore <=
        // timestampNow and notValidAfter <= timestampNow holds. The before() and after() methods do not cover these
        // cases.
        return certificateEntity.getNotValidBefore().compareTo(timestampNow) <= 0 &&
                certificateEntity.getNotValidAfter().compareTo(timestampNow) >= 0 &&
                certificateEntity.getStatus() == CertificateStatus.VALID;
    }

    private void storeCertificate(Certificate certificate, String userId, String use) {
        final UseEntity useEntity = fetchUseEntity(use);

        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setUserId(userId);
        certificateEntity.setSubject(certificate.getSubject().toString());
        certificateEntity.setSerial(certificate.getSerial());
        certificateEntity.setNotValidBefore(dateToTimestamp(certificate.getValidFrom()));
        certificateEntity.setNotValidAfter(dateToTimestamp(certificate.getValidTo()));
        certificateEntity.setX509PEMCertificate(certificateToByteArray(certificate));
        certificateEntity.setUse(useEntity);

        try {
            certificateRepository.save(certificateEntity);
            log.info("Stored signed certificate '{}'", certificateEntity.getSubject());
        } catch (ConstraintViolationException e) {
            final String subjectString = certificate.getSubject().toString();
            log.error("Error persisting certificate '{}' with serial '{}': {}", subjectString,
                    certificate.getSerial().toString(), e.getMessage());
            throw new CertificateAlreadyExistsException(String.format("Certificate already exists: %s", subjectString));
        }
    }

    private UseEntity fetchUseEntity(String use) {
        final Optional<UseEntity> useOptional = useRepository.findOne(use);
        return useOptional.orElseGet(() -> {
            final Optional<UseEntity> defaultUseOptional = useRepository.findOne(UseEntity.DEFAULT_USE);
            return defaultUseOptional.orElseThrow(() -> {
                log.error("Default use '{}' not found", UseEntity.DEFAULT_USE);
                return new SigningServiceException("Default use not found");
            });
        });
    }

    private Timestamp dateToTimestamp(Date date) {
        return new Timestamp(date.getTime());
    }

    private byte[] certificateToByteArray(Certificate certificate) {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(byteArrayOutputStream)) {
            final PEMCertificateWriter pemCertificateWriter = new PEMCertificateWriter(outputStreamWriter);
            pemCertificateWriter.writeCertificate(certificate);

            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            log.error("Cannot write certificate to byte array: {}", e.getMessage());
            throw new SigningServiceException("Cannot store certificate");
        }
    }
}
