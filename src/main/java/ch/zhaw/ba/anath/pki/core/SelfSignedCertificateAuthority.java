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

package ch.zhaw.ba.anath.pki.core;

import ch.zhaw.ba.anath.pki.core.exceptions.SelfSignedCACreationException;
import ch.zhaw.ba.anath.pki.core.extensions.CertificateExtensionsActions;
import ch.zhaw.ba.anath.pki.core.extensions.CertificateExtensionsActionsFactoryInterface;
import ch.zhaw.ba.anath.pki.core.extensions.ExtensionArguments;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateSerialProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateValidityProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SecureRandomProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SignatureNameProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Create a self-signed, self-issued Certificate and Private Key using RSA.
 *
 * @author Rafael Ostertag
 */
public class SelfSignedCertificateAuthority {
    public static final int MIN_KEY_SIZE = 1024;
    private final SelfSignedCANameBuilder selfSignedCANameBuilder;
    private final CertificateValidityProvider certificateValidityProvider;
    private final CertificateSerialProvider certificateSerialProvider;
    private final SecureRandomProvider secureRandomProvider;
    private final SignatureNameProvider signatureNameProvider;
    private final CertificateExtensionsActions certificateExtensionsActions;
    private final int keySize;
    private KeyPair keyPair;
    private Certificate certificate;
    private boolean created = false;

    /**
     * @param selfSignedCANameBuilder     A prepared {@link SelfSignedCANameBuilder} providing the subject and issuer of
     *                                    the self-signed, self-issued certificate.
     * @param certificateValidityProvider A {@link CertificateValidityProvider} instance providing the temporal
     *                                    certificateValidity period of the self-signed, self-issued certificate.
     * @param certificateSerialProvider   A {@link CertificateSerialProvider} instance providing the serial number for
     *                                    the self-signed, self-issued certificate.
     * @param secureRandomProvider        A {@link SecureRandomProvider} instance providing a secure random generator
     *                                    for
     *                                    key material.
     * @param signatureNameProvider       A {@link SignatureNameProvider} instance providing the algorithm name for
     *                                    signing the self-signed, self-issued certificate.
     * @param certificateExtensionsActions An implementation of
     * {@link CertificateExtensionsActionsFactoryInterface}.
     * @param keySize                     the key size in bits. Must be greater than {@value #MIN_KEY_SIZE}.
     *
     * @throws SelfSignedCACreationException when key size is smaller than {@value #MIN_KEY_SIZE}.
     */
    public SelfSignedCertificateAuthority(SelfSignedCANameBuilder selfSignedCANameBuilder,
                                          CertificateValidityProvider certificateValidityProvider,
                                          CertificateSerialProvider certificateSerialProvider, SecureRandomProvider
                                                  secureRandomProvider, SignatureNameProvider signatureNameProvider,
                                          CertificateExtensionsActionsFactoryInterface certificateExtensionsActions,
                                          int keySize) {
        this.selfSignedCANameBuilder = selfSignedCANameBuilder;
        this.certificateValidityProvider = certificateValidityProvider;
        this.certificateSerialProvider = certificateSerialProvider;
        this.secureRandomProvider = secureRandomProvider;
        this.signatureNameProvider = signatureNameProvider;
        this.certificateExtensionsActions = certificateExtensionsActions.getInstance();
        validateKeySizeOrThrow(keySize);

        this.keySize = keySize;
    }

    private void validateKeySizeOrThrow(int keySize) {
        if (keySize < MIN_KEY_SIZE) {
            throw new SelfSignedCACreationException(String.format("Key size %d is smaller than minimum key size %d",
                    keySize, MIN_KEY_SIZE));
        }

        final HashSet<Integer> validKeySizes = new HashSet<>(Arrays.asList(512, 1024, 2048, 4096));
        if (!validKeySizes.contains(keySize)) {
            throw new SelfSignedCACreationException(String.format("Key size %d is not in list of allowed key sizes: " +
                    "%s", keySize, validKeySizes.toString()));
        }
    }

    public CertificateAuthority getCertificateAuthority() {
        if (!created) {
            create();
        }
        return new CertificateAuthority(keyPair.getPrivate(), certificate);
    }

    void create() {
        if (created) return;

        createKeyPair();
        selfSignPublicKey();

        created = true;
    }

    private void selfSignPublicKey() {
        assert keyPair != null;

        final X500Name issuer = selfSignedCANameBuilder.toX500Name();
        final X500Name subject = selfSignedCANameBuilder.toX500Name();
        final BigInteger serial = certificateSerialProvider.serial();

        final ExtensionArguments extensionArguments = new ExtensionArguments();
        extensionArguments.setCertificateAuthority(null);
        extensionArguments.setSubjectName(subject);
        extensionArguments.setSubjectSerial(serial);
        extensionArguments.setSubjectKeyPair(keyPair);

        final X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                certificateValidityProvider.from(),
                certificateValidityProvider.to(),
                subject,
                keyPair.getPublic()
        );

        certificateExtensionsActions.apply(x509v3CertificateBuilder, extensionArguments);

        final X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(initializeContentSigner());
        this.certificate = new Certificate(x509CertificateHolder);
    }

    private ContentSigner initializeContentSigner() {
        try {
            return new JcaContentSignerBuilder(signatureNameProvider.signatureName())
                    .setProvider(signatureNameProvider.providerName())
                    .build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new SelfSignedCACreationException("Error creating the signer: " + e.getMessage(), e);
        }
    }

    private void createKeyPair() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize, secureRandomProvider.getSecureRandom());
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new SelfSignedCACreationException("Error instantiating RSA KeyGenerator");
        }
    }
}
