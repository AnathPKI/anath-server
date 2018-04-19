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

import ch.zhaw.ba.anath.pki.core.interfaces.CAWriter;
import ch.zhaw.ba.anath.pki.core.interfaces.CertificateWriter;
import ch.zhaw.ba.anath.pki.core.interfaces.PrivateKeyWriter;

/**
 * Write a given {@link CertificateAuthority} PEM encoded to persistent storage.
 *
 * @author Rafael Ostertag
 */
public final class PEMCertificateAuthorityWriter implements CAWriter {
    private final CertificateWriter certificateWriter;
    private final PrivateKeyWriter privateKeyWriter;

    public PEMCertificateAuthorityWriter(CertificateWriter certificateWriter, PrivateKeyWriter privateKeyWriter) {
        this.certificateWriter = certificateWriter;
        this.privateKeyWriter = privateKeyWriter;
    }

    @Override
    public void writeCA(CertificateAuthority certificateAuthority) {
        certificateWriter.writeCertificate(certificateAuthority.getCertificate());
        privateKeyWriter.writePrivateKey(certificateAuthority.getPrivateKey());
    }
}
