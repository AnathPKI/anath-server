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

import ch.zhaw.ba.anath.pki.core.exceptions.RevocationListSignerException;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateRevocationListValidityProvider;
import ch.zhaw.ba.anath.pki.core.interfaces.SignatureNameProvider;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

/**
 * Create a Certificate Revocation List.
 *
 * @author Rafael Ostertag
 */
public class CertificateRevocationListCreator {
    private final SignatureNameProvider signatureNameProvider;
    private final ContentSigner contentSigner;
    private final CertificateAuthority certificateAuthority;
    private final CertificateRevocationListValidityProvider certificateRevocationListValidityProvider;

    public CertificateRevocationListCreator(SignatureNameProvider signatureNameProvider, CertificateAuthority
            certificateAuthority, CertificateRevocationListValidityProvider certificateRevocationListValidityProvider) {
        this.signatureNameProvider = signatureNameProvider;
        this.certificateAuthority = certificateAuthority;
        this.certificateRevocationListValidityProvider = certificateRevocationListValidityProvider;
        this.contentSigner = initializeContentSigner();
    }

    private ContentSigner initializeContentSigner() {
        try {
            return new JcaContentSignerBuilder(signatureNameProvider.signatureName())
                    .setProvider(signatureNameProvider.providerName())
                    .build(certificateAuthority.getPrivateKey());
        } catch (OperatorCreationException e) {
            throw new RevocationListSignerException("Error creating the signer: " + e.getMessage(), e);
        }
    }

    /**
     * Create a {@link CertificateRevocationList}. The {@code thisUpdate} and {@code nextUpdate} fields in the X.509
     * CRL are computed using the provided {@link CertificateRevocationListValidityProvider}.
     *
     * @param revokedCertificates {@link List} of {@link RevokedCertificate}.
     *
     * @return a {@link CertificateRevocationList} instance
     */
    public CertificateRevocationList create(List<RevokedCertificate> revokedCertificates) {
        final Date thisUpdate = certificateRevocationListValidityProvider.thisUpdate();
        final Date nextUpdate = certificateRevocationListValidityProvider.nextUpdate();
        final X509v2CRLBuilder x509v2CRLBuilder = new X509v2CRLBuilder(certificateAuthority.getCASubjectName(),
                thisUpdate);
        x509v2CRLBuilder.setNextUpdate(nextUpdate);

        for (RevokedCertificate revokedCertificate : revokedCertificates) {
            final BigInteger certificateSerial = revokedCertificate.getCertificate().getSerial();
            x509v2CRLBuilder.addCRLEntry(certificateSerial, revokedCertificate.getRevocationTime(), CRLReason
                    .unspecified);
        }

        final X509CRLHolder x509CRLHolder = x509v2CRLBuilder.build(contentSigner);
        return new CertificateRevocationList(x509CRLHolder, thisUpdate, nextUpdate);
    }
}
