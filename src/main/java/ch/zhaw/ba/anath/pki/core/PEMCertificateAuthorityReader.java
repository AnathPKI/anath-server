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

import ch.zhaw.ba.anath.pki.core.interfaces.CertificateAuthorityReader;

import java.io.Reader;
import java.security.PrivateKey;

/**
 * @author Rafael Ostertag
 */
public final class PEMCertificateAuthorityReader implements CertificateAuthorityReader {

    private final CertificateAuthority certificateAuthority;

    public PEMCertificateAuthorityReader(Reader caPrivateKey, Reader caCertificate) {
        final PEMPrivateKeyReader pemPrivateKeyReader = new PEMPrivateKeyReader(caPrivateKey);
        final PrivateKey privateKey = pemPrivateKeyReader.privateKey();

        final PEMCertificateReader pemCertificateReader = new PEMCertificateReader(caCertificate);
        final Certificate certificate = pemCertificateReader.certificate();

        this.certificateAuthority = new CertificateAuthority(privateKey, certificate);
    }

    @Override
    public CertificateAuthority certificateAuthority() {
        return certificateAuthority;
    }
}
