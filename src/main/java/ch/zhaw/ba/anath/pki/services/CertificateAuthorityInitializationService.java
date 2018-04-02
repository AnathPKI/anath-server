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
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateSerialProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateValidityProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SecureRandomProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SignatureNameProvider;
import ch.zhaw.ba.anath.pki.dto.CreateSelfSignedCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.dto.ImportCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityAlreadyInitializedException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityImportException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityInitializationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.util.Base64;
import java.util.Optional;

import static ch.zhaw.ba.anath.pki.services.CertificateAuthorityService.SECURE_STORE_CA_CERTIFICATE;
import static ch.zhaw.ba.anath.pki.services.CertificateAuthorityService.SECURE_STORE_CA_PRIVATE_KEY;

/**
 * Initializes the Certificate Authority by creating a self-signed CA or by importing a CA from a PKCS#12 structure.
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class CertificateAuthorityInitializationService {
    private static final String CERTIFICATE_AUTHORITY_ALREADY_INITIALIZED_MESSAGE = "Certificate Authority already " +
            "initialized";
    private final SecureStoreService secureStoreService;
    private final CertificateSerialProvider certificateSerialProvider;
    private final SecureRandomProvider secureRandomProvider;
    private final SignatureNameProvider signatureNameProvider;
    private final RevocationService revocationService;

    public CertificateAuthorityInitializationService(SecureStoreService secureStoreService,
                                                     CertificateSerialProvider certificateSerialProvider,
                                                     SecureRandomProvider secureRandomProvider,
                                                     SignatureNameProvider signatureNameProvider, RevocationService
                                                             revocationService) {
        this.secureStoreService = secureStoreService;
        this.certificateSerialProvider = certificateSerialProvider;
        this.secureRandomProvider = secureRandomProvider;
        this.signatureNameProvider = signatureNameProvider;
        this.revocationService = revocationService;
    }

    /**
     * Import a PKCS#12 Certificate Authority private key and certificate.
     *
     * @param importCertificateAuthorityDto {@link ImportCertificateAuthorityDto} instance.
     *                                      {@link ImportCertificateAuthorityDto#pkcs12} must be Base64 encoded.
     */
    public void importPkcs12CertificateAuthority(ImportCertificateAuthorityDto importCertificateAuthorityDto) {
        testEmptyCertificateAuthorityOrThrow();

        log.info("Decode Base64 encoded PKCS#12 object");
        final byte[] decodedPkcs12Ca = decodeBase64EncodedPKCS12Structure(importCertificateAuthorityDto.getPkcs12());
        log.info("Extract Certificate Authority from PKCS#12 structure");
        final CertificateAuthority certificateAuthority = extractCertificateAuthorityFromPkcs12Structure
                (decodedPkcs12Ca, importCertificateAuthorityDto.getPassword());

        importCertificateAuthorityIntoSecureStore(certificateAuthority);
        log.info("Imported Certificate Authority: {}", certificateAuthority.getCertificate().getSubject().toString());

        createInitialRevocationList();
    }

    public void createSelfSignedCertificateAuthority(CreateSelfSignedCertificateAuthorityDto
                                                             createSelfSignedCertificateAuthorityDto) {
        testEmptyCertificateAuthorityOrThrow();

        final SelfSignedCANameBuilder selfSignedCANameBuilder = makeSelfSignedNameBuilder
                (createSelfSignedCertificateAuthorityDto);
        final String caName = selfSignedCANameBuilder.toX500Name().toString();
        log.info("Self Signed Certificate Authority name: {}", caName);

        final CertificateValidityProvider validityProvider = new ConfigurablePeriodValidity
                (createSelfSignedCertificateAuthorityDto.getValidDays());

        final SelfSignedCertificateAuthority selfSignedCertificateAuthority = new SelfSignedCertificateAuthority
                (selfSignedCANameBuilder, validityProvider, certificateSerialProvider,
                        secureRandomProvider, signatureNameProvider, createSelfSignedCertificateAuthorityDto.getBits());

        log.info("Self Signed Certificate Authority valid from {} to {}",
                selfSignedCertificateAuthority.getCertificateAuthority().getCertificate().getValidFrom(),
                selfSignedCertificateAuthority.getCertificateAuthority().getCertificate().getValidTo());
        final CertificateAuthority certificateAuthority = selfSignedCertificateAuthority.getCertificateAuthority();
        log.info("Self Signed Certificate Authority {} created", caName);

        importCertificateAuthorityIntoSecureStore(certificateAuthority);
        log.info("Self Signed Certificate Authority {} imported", caName);

        createInitialRevocationList();
    }

    private void createInitialRevocationList() {
        log.info("Create initial revocation list");
        revocationService.updateCertificateRevocationList();
    }

    SelfSignedCANameBuilder makeSelfSignedNameBuilder(CreateSelfSignedCertificateAuthorityDto
                                                              createSelfSignedCertificateAuthorityDto) {

        final SelfSignedCANameBuilder.SelfSignedCANameBuilderBuilder builder = SelfSignedCANameBuilder.builder();

        Optional<String> value = getString(createSelfSignedCertificateAuthorityDto.getCommonName());
        value.ifPresent(builder::commonName);

        value = getString(createSelfSignedCertificateAuthorityDto.getCountry());
        value.ifPresent(builder::country);

        value = getString(createSelfSignedCertificateAuthorityDto.getLocation());
        value.ifPresent(builder::location);

        value = getString(createSelfSignedCertificateAuthorityDto.getOrganization());
        value.ifPresent(builder::organization);

        value = getString(createSelfSignedCertificateAuthorityDto.getOrganizationalUnit());
        value.ifPresent(builder::organizationalUnit);

        value = getString(createSelfSignedCertificateAuthorityDto.getState());
        value.ifPresent(builder::state);

        return builder.build();
    }

    private Optional<String> getString(String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(value);
    }

    private byte[] decodeBase64EncodedPKCS12Structure(String base64EncodedPKCS12) {
        try {
            final Base64.Decoder decoder = Base64.getDecoder();
            return decoder.decode(base64EncodedPKCS12);
        } catch (IllegalArgumentException firstException) {
            log.info("Error decoding PKCS#12 object using the Basic Type Base64 decoder, trying MIME Type Base64 " +
                    "decoder: {}", firstException.getMessage());
            try {
                final Base64.Decoder decoder = Base64.getMimeDecoder();
                return decoder.decode(base64EncodedPKCS12);
            } catch (IllegalArgumentException secondException) {
                log.error("Unable to decode base64 encoding using either Basic or MIME type encoder: {}",
                        secondException
                                .getMessage());
                throw new CertificateAuthorityImportException("Unable to decode the Base64 encoded PKCS#12 structure");
            }
        }
    }

    private void importCertificateAuthorityIntoSecureStore(CertificateAuthority certificateAuthority) {
        ByteArrayOutputStream caKeyByteArrayOutputStream = new ByteArrayOutputStream();
        ByteArrayOutputStream caCertificateArrayOutputStream = new ByteArrayOutputStream();
        try (OutputStreamWriter caKeyOutputStreamWriter = new OutputStreamWriter(caKeyByteArrayOutputStream);
             OutputStreamWriter caCertificateOutputStreamWriter = new OutputStreamWriter
                     (caCertificateArrayOutputStream)) {

            final PEMCertificateAuthorityWriter pemCertificateAuthorityWriter = new PEMCertificateAuthorityWriter(new
                    PEMCertificateWriter(caCertificateOutputStreamWriter), new
                    PEMPrivateKeyWriter(caKeyOutputStreamWriter));

            pemCertificateAuthorityWriter.writeCA(certificateAuthority);
        } catch (Exception e) {
            log.error("Error importing Certificate Authority into secure store: {}", e.getMessage());
            throw new CertificateAuthorityInitializationException("Error importing Certificate Authority into secure " +
                    "store", e);
        }

        secureStoreService.put(SECURE_STORE_CA_PRIVATE_KEY, caKeyByteArrayOutputStream.toByteArray());
        secureStoreService.put(SECURE_STORE_CA_CERTIFICATE, caCertificateArrayOutputStream.toByteArray());
    }

    private CertificateAuthority extractCertificateAuthorityFromPkcs12Structure(byte[] decodedPkcs12Ca, String
            password) {
        try (ByteArrayInputStream pkcs12ArrayInputStream = new ByteArrayInputStream(decodedPkcs12Ca)) {

            final PKCS12CertificateAuthorityReader pkcs12CertificateAuthorityReader = new
                    PKCS12CertificateAuthorityReader(pkcs12ArrayInputStream, password);

            return pkcs12CertificateAuthorityReader.certificateAuthority();
        } catch (Exception e) {
            log.error("Error extracting Certificate Authority from PKCS#12 structure: {}", e.getMessage());
            throw new CertificateAuthorityImportException("Error importing Certificate Authority from PKCS#12 " +
                    "structure", e);
        }
    }

    private void testEmptyCertificateAuthorityOrThrow() {
        final Optional<Byte[]> privateKey = secureStoreService.get(SECURE_STORE_CA_PRIVATE_KEY);
        if (privateKey.isPresent()) {
            log.error("Certificate Authority private key already existing");
            throw new CertificateAuthorityAlreadyInitializedException
                    (CERTIFICATE_AUTHORITY_ALREADY_INITIALIZED_MESSAGE);
        }

        final Optional<Byte[]> certificate = secureStoreService.get(SECURE_STORE_CA_CERTIFICATE);
        if (certificate.isPresent()) {
            log.error("Certificate Authority certificate already existing");
            throw new CertificateAuthorityAlreadyInitializedException
                    (CERTIFICATE_AUTHORITY_ALREADY_INITIALIZED_MESSAGE);
        }
    }
}
