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

package ch.zhaw.ba.anath.pki.core;

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateConstraintException;
import ch.zhaw.ba.anath.pki.core.exceptions.CertificateSignerException;
import ch.zhaw.ba.anath.pki.core.interfaces.*;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

/**
 * Sign a X.509 certificate. It uses {@link UuidCertificateSerialProvider} as {@link CertificateSerialProvider}, and
 * {@link OneYearValidity} as {@link CertificateValidityProvider}, and {@link OrganizationCertificateConstraint} as
 * {@link CertificateConstraintProvider}.
 *
 * @author Rafael Ostertag
 */
public class CertificateSigner {
    private final SignatureNameProvider signatureNameProvider;
    private final ContentSigner contentSigner;
    private final CertificateAuthority certificateAuthority;
    @Setter
    private CertificateConstraintProvider certificateConstraintProvider;
    @Setter
    private CertificateSerialProvider certificateSerialProvider;
    @Setter
    private CertificateValidityProvider validityProvider;

    /**
     * Constructs a Certificate Signer.
     * <p>
     * After construction, following attributes may be set
     * <ul>
     * <li>{@link CertificateConstraintProvider}</li>
     * <li>{@link CertificateSerialProvider}</li>
     * <li>{@link CertificateValidityProvider}</li>
     * </ul>
     * <p>
     * If not explicitly set, they remain at their defaults.
     *
     * @param signatureNameProvider The {@link SignatureNameProvider}.
     * @param certificateAuthority  The {@link CertificateAuthority}
     *
     * @throws CertificateSignerException upon error initializing the signer.
     */
    public CertificateSigner(SignatureNameProvider signatureNameProvider, CertificateAuthority certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
        this.signatureNameProvider = signatureNameProvider;
        this.contentSigner = initializeContentSigner();

        this.certificateConstraintProvider = new OrganizationCertificateConstraint();
        this.certificateSerialProvider = new UuidCertificateSerialProvider();
        this.validityProvider = new OneYearValidity();
    }

    private ContentSigner initializeContentSigner() {
        try {
            return new JcaContentSignerBuilder(signatureNameProvider.signatureName())
                    .setProvider(signatureNameProvider.providerName())
                    .build(certificateAuthority.getPrivateKey());
        } catch (OperatorCreationException e) {
            throw new CertificateSignerException("Error creating the signer: " + e.getMessage(), e);
        }
    }

    /**
     * Sign the certification request with the Certificate Authority's private key.
     *
     * @param certificateSigningRequest {@link CertificateSigningRequestReader} instance to be signed.
     *
     * @return {@link Certificate} instance.
     *
     * @throws CertificateConstraintException when certificate constraints are not met.
     */
    public Certificate signCertificate(CertificateSigningRequest certificateSigningRequest) {
        final X500Name issuerName = certificateAuthority.getCASubjectName();

        certificateConstraintProvider.validateSubject(certificateSigningRequest.getSubject(), issuerName);

        final BigInteger serial = certificateSerialProvider.serial();
        final Date from = validityProvider.from();
        final Date to = validityProvider.to();
        final X500Name subject = certificateSigningRequest.getSubject();

        final X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
                issuerName,
                serial,
                from,
                to,
                subject,
                getSubjectPublicKeyInfoFromCertificateSigningRequest(certificateSigningRequest)
        );
        setBasicConstraints(x509v3CertificateBuilder);
        final X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(contentSigner);

        return new Certificate(certificateHolder);
    }

    private void setBasicConstraints(X509v3CertificateBuilder x509v3CertificateBuilder) {
        try {
            x509v3CertificateBuilder.addExtension(
                    new Extension(Extension.basicConstraints, true,
                            new BasicConstraints(false).getEncoded()));
        } catch (IOException e) {
            throw new CertificateSignerException("Error building certificate: " + e.getMessage(), e);
        }
    }

    private SubjectPublicKeyInfo getSubjectPublicKeyInfoFromCertificateSigningRequest(CertificateSigningRequest
                                                                                              certificateSigningRequest) {
        return certificateSigningRequest.getPkcs10CertificationRequest().getSubjectPublicKeyInfo();
    }
}
