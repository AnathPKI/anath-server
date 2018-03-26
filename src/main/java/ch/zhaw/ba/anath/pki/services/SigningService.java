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

import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.core.CertificateAuthority;
import ch.zhaw.ba.anath.pki.core.CertificateSigner;
import ch.zhaw.ba.anath.pki.core.PEMCertificateAuthorityReader;
import ch.zhaw.ba.anath.pki.core.interfaces.*;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityInitializationException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.util.Optional;

/**
 * Sign and store CSR.
 *
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class SigningService {
    public static final String SECURE_STORE_CA_PRIVATE_KEY = "ca.key";
    public static final String SECURE_STORE_CA_CERTIFICATE = "ca.cert";
    private final SecureStoreService secureStoreService;
    private final CertificateRepository certificateRepository;
    private CertificateAuthority certificateAuthority = null;
    private CertificateSigner certificateSigner = null;
    private CertificateConstraintProvider certificateConstraintProvider;
    private SignatureNameProvider signatureNameProvider;
    private CertificateValidityProvider certificateValidityProvider;
    private CertificateSerialProvider certificateSerialProvider;

    public SigningService(SecureStoreService secureStoreService, CertificateRepository certificateRepository) {
        this.secureStoreService = secureStoreService;
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setCertificateValidityProvider(CertificateValidityProvider certificateValidityProvider) {
        this.certificateValidityProvider = certificateValidityProvider;
    }

    @Autowired
    public void setCertificateSerialProvider(CertificateSerialProvider certificateSerialProvider) {
        this.certificateSerialProvider = certificateSerialProvider;
    }

    @Autowired
    public void setCertificateConstraintProvider(CertificateConstraintProvider certificateConstraintProvider) {
        this.certificateConstraintProvider = certificateConstraintProvider;
    }

    @Autowired
    public void setSignatureNameProvider(SignatureNameProvider signatureNameProvider) {
        this.signatureNameProvider = signatureNameProvider;
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
        final Optional<Byte[]> caPrivateKeyOptional = secureStoreService.get(SECURE_STORE_CA_PRIVATE_KEY);
        return caPrivateKeyOptional.orElseThrow(() -> {
            log.error("Unable to retrieve certificate authority private key from secure storage");
            return new CertificateAuthorityInitializationException("No CA private key found");
        });
    }

    private Byte[] retrieveCaCertificateFromSecureStoreOrThrow() {
        final Optional<Byte[]> caCertificateOptional = secureStoreService.get(SECURE_STORE_CA_CERTIFICATE);
        return caCertificateOptional.orElseThrow(() -> {
            log.error("Unable to retrieve certificate authority certificate from secure storage");
            return new CertificateAuthorityInitializationException("No CA certificate found");
        });
    }

    public Certificate signCertificate(CertificateSigningRequestReader certificateSigningRequestReader) {
        initializeCertificateSigner();
        return certificateSigner.signCertificate(certificateSigningRequestReader);
    }
}
