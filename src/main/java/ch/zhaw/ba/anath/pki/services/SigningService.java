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

import ch.zhaw.ba.anath.pki.core.*;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateConstraintProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateSerialProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateValidityProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SignatureNameProvider;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyExistsException;
import ch.zhaw.ba.anath.pki.exceptions.SigningException;
import ch.zhaw.ba.anath.pki.repositories.UseRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Optional;

/**
 * Sign a CSR and store the certificate. The {@link CertificateAuthority} is created on first use and kept in memory.
 * Thus be careful when changing the CA private key and certificate, you need to restart the application.
 *
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class SigningService {
    private final CertificateAuthorityService certificateAuthorityService;
    private final ConfirmableCertificatePersistenceLayer confirmableCertificatePersistenceLayer;
    private final UseRepository useRepository;
    private final CertificateConstraintProvider certificateConstraintProvider;
    private final SignatureNameProvider signatureNameProvider;
    private final CertificateValidityProvider certificateValidityProvider;
    private final CertificateSerialProvider certificateSerialProvider;
    private final CertificateUniquenessService certificateUniquenessService;
    private final ConfirmationNotificationService confirmationNotificationService;
    private CertificateAuthority certificateAuthority = null;
    private CertificateSigner certificateSigner = null;

    public SigningService(CertificateAuthorityService certificateAuthorityService,
                          ConfirmableCertificatePersistenceLayer confirmableCertificatePersistenceLayer,
                          UseRepository useRepository,
                          CertificateConstraintProvider certificateConstraintProvider,
                          SignatureNameProvider signatureNameProvider,
                          CertificateValidityProvider certificateValidityProvider,
                          CertificateSerialProvider certificateSerialProvider, CertificateUniquenessService
                                  certificateUniquenessService, ConfirmationNotificationService
                                  confirmationNotificationService) {
        this.certificateAuthorityService = certificateAuthorityService;
        this.confirmableCertificatePersistenceLayer = confirmableCertificatePersistenceLayer;
        this.useRepository = useRepository;
        this.certificateConstraintProvider = certificateConstraintProvider;
        this.signatureNameProvider = signatureNameProvider;
        this.certificateValidityProvider = certificateValidityProvider;
        this.certificateSerialProvider = certificateSerialProvider;
        this.certificateUniquenessService = certificateUniquenessService;
        this.confirmationNotificationService = confirmationNotificationService;
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
        log.info("Initialized and cached certificate signer");
    }

    /**
     * Initialize the CertificateAuthority. It can be called multiple times. Once the {@link CertificateAuthority}
     * has been initialized, it won't be initialized again.
     */
    private void initializeCertificateAuthority() {
        if (certificateAuthority != null) {
            return;
        }

        log.info("Load and cache certificate authority");
        certificateAuthority = certificateAuthorityService.getCertificateAuthority();
    }

    /**
     * Sign a CSR.
     * <p>
     * The CSR will be signed and tentatively added to a stoer. If the subject of the CSR already exists and the
     * certificate is non-revoked and non-expired, the signing process will be aborted and an exception thrown.
     * <p>
     * Besides exception mentioned below,  {@link ch.zhaw.ba.anath.pki.core.exceptions.PKIException} may be thrown.
     *
     * @param certificateSigningRequest the {@link Reader} providing the CSR.
     * @param userId                          the user id of the user the certificate belongs to.
     * @param use                             the use. If the use cannot be found in the database, the {@value
     *                                        UseEntity#DEFAULT_USE} is used.
     *
     * @return Confirmation token. This is used to confirm the certificate.
     *
     * @throws CertificateAlreadyExistsException when a non-revoked, non-expired for the given subject already
     *                                           exists, or the serial number is taken.
     * @throws SigningException           if no default certificate use can be found.
     */

    public String tentativelySignCertificate(CertificateSigningRequest certificateSigningRequest,
                                             String userId, String use) {
        initializeCertificateSigner();

        final String subject = certificateSigningRequest.getSubject().toString();
        log.info("Test uniqueness of certificate '{}'", subject);
        certificateUniquenessService.testCertificateUniquenessInCertificateRepositoryOrThrow(subject);

        log.info("Sign certificate signing request '{}'", subject);
        final Certificate certificate = certificateSigner.signCertificate(certificateSigningRequest);

        log.info("Signed certificate '{}'", subject);

        log.info("Store signed certificate '{}'", subject);
        final String token = storeCertificate(certificate, userId, use);

        confirmationNotificationService.sendMail(token, userId);

        return token;
    }

    /**
     * Confirm a tentatively signed certificate.
     *
     * @param token  token as received by {@link #tentativelySignCertificate(CertificateSigningRequest, String, String)}
     * @param userId the user id the token belongs to.
     *
     * @return the {@link Certificate} instance.
     */
    public Certificate confirmTentativelySignedCertificate(String token, String userId) {
        final CertificateEntity confirmedCertificate = confirmableCertificatePersistenceLayer.confirm(token, userId);
        final InputStream memoryStream = new ByteArrayInputStream(confirmedCertificate.getX509PEMCertificate());
        try (Reader pemCertificateStreamReader = new InputStreamReader(memoryStream)) {
            final PEMCertificateReader pemCertificateReader = new PEMCertificateReader(pemCertificateStreamReader);
            return pemCertificateReader.certificate();
        } catch (IOException e) {
            log.error("Error reading certificate from PEM: {}", e.getMessage());
            throw new SigningException("Error reading certificate");
        }
    }



    private String storeCertificate(Certificate certificate, String userId, String use) {
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

        return confirmableCertificatePersistenceLayer.store(certificateEntity);
    }

    private UseEntity fetchUseEntity(String use) {
        final Optional<UseEntity> useOptional = useRepository.findOne(use);
        return useOptional.orElseGet(() -> {
            final Optional<UseEntity> defaultUseOptional = useRepository.findOne(UseEntity.DEFAULT_USE);
            return defaultUseOptional.orElseThrow(() -> {
                log.error("Default use '{}' not found", UseEntity.DEFAULT_USE);
                return new SigningException("Default use not found");
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
            throw new SigningException("Cannot store certificate");
        }
    }
}
