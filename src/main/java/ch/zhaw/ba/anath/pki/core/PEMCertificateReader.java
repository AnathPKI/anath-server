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

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateReaderException;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateReader;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

import java.io.Reader;

/**
 * Read a X.509 certificate from a PEM file.
 *
 * @author Rafael Ostertag
 */
public final class PEMCertificateReader implements CertificateReader {

    private final Certificate cert;

    public PEMCertificateReader(Reader certificate) {
        this.cert = new Certificate(readPEMCertificate(certificate));
    }

    @Override
    public Certificate certificate() {
        return cert;
    }

    private X509CertificateHolder readPEMCertificate(Reader certificate) {
        try (PEMParser pemParser = new PEMParser(certificate)) {
            final Object pemObject = pemParser.readObject();
            return getX509CertificateHolderFromObject(pemObject);
        } catch (Exception e) {
            throw new CertificateReaderException("Error reading PEM encoded certificate: " + e.getMessage(), e);
        }
    }

    private X509CertificateHolder getX509CertificateHolderFromObject(Object pemObject) {
        if (!(pemObject instanceof X509CertificateHolder)) {
            throw new CertificateReaderException("Certificate is not a X.509 certificate");
        }

        return (X509CertificateHolder) pemObject;
    }
}
