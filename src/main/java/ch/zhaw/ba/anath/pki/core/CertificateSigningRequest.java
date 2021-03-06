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

import ch.zhaw.ba.anath.pki.core.exceptions.CSRSignatureException;
import ch.zhaw.ba.anath.pki.core.exceptions.CertificateSigningRequestReaderException;
import lombok.Value;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequest;

/**
 * Abstraction of {@link PKCS10CertificationRequest}. Upon initialization, it verifies the signature of the CSR.
 *
 * @author Rafael Ostertag
 */
@Value
public class CertificateSigningRequest {
    private final PKCS10CertificationRequest pkcs10CertificationRequest;

    public CertificateSigningRequest(PKCS10CertificationRequest pkcs10CertificationRequest) {
        verifySignatureOrThrow(pkcs10CertificationRequest);
        this.pkcs10CertificationRequest = pkcs10CertificationRequest;
    }

    public X500Name getSubject() {
        return pkcs10CertificationRequest.getSubject();
    }

    private void verifySignatureOrThrow(PKCS10CertificationRequest csr) {
        BcPKCS10CertificationRequest bcPKCS10CertificationRequest = new BcPKCS10CertificationRequest(csr);

        try {
            ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(
                    new DefaultDigestAlgorithmIdentifierFinder()
            ).build(bcPKCS10CertificationRequest.getPublicKey());

            boolean isSignatureValid = csr.isSignatureValid(contentVerifierProvider);
            if (!isSignatureValid) {
                throw new CSRSignatureException(String.format("Error verifying signature on CSR for %s", csr
                        .getSubject()
                        .toString()));
            }
        } catch (OperatorCreationException e) {
            throw new CertificateSigningRequestReaderException("Cannot verify signature of CSR", e);
        } catch (PKCSException e) {
            throw new CertificateSigningRequestReaderException("Cannot extract public key from CSR", e);
        }
    }
}
