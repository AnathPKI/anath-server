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

import ch.zhaw.ba.anath.pki.core.CertificateAuthority;
import ch.zhaw.ba.anath.pki.core.PEMCertificateAuthorityReader;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.util.Optional;

/**
 * Get the CA as {@link CertificateAuthority} or the CA Certificate in PEM encoding.
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class CertificateAuthorityService {
    public static final String SECURE_STORE_CA_PRIVATE_KEY = "ca.key";
    public static final String SECURE_STORE_CA_CERTIFICATE = "ca.cert";

    private final SecureStoreService secureStoreService;

    public CertificateAuthorityService(SecureStoreService secureStoreService) {
        this.secureStoreService = secureStoreService;
    }

    /**
     * Retrieve the CA certificate.
     *
     * @return return the PEM encoded certificate as string.
     */
    public String getCertificate() {
        final Optional<Byte[]> optionalCaCertificate = secureStoreService.get(SECURE_STORE_CA_CERTIFICATE);

        final Byte[] caCertificate = optionalCaCertificate.orElseThrow(() -> {
            log.error("Unable to get Certificate Authority certificate, Certificate Authority not initialized");
            return new
                    CertificateAuthorityNotInitializedException("Not initialized");
        });

        return new String(ArrayUtils.toPrimitive(caCertificate));
    }

    public CertificateAuthority getCertificateAuthority() {
        log.info("Load certificate authority");
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
        return pemCertificateAuthorityReader.certificateAuthority();
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
}
