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

package ch.zhaw.ba.anath.pki.core.extensions;

import ch.zhaw.ba.anath.pki.core.exceptions.SelfSignedCACreationException;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.security.NoSuchAlgorithmException;

/**
 * @author Rafael Ostertag
 */
public class CaSubjectKeyIdentifierExtensionProvider implements CertificateAuthorityExtensionProvider {
    @Override
    public X509v3CertificateBuilder addExtension(X509v3CertificateBuilder certificateBuilder, ExtensionArguments
            extensionArguments) {

        try {
            final byte[] subjectKeyId = CaAuthorityKeyIdentifierExtensionProvider.makeSubjectKeyId(extensionArguments);
            final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(subjectKeyId);

            return certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        } catch (CertIOException | NoSuchAlgorithmException e) {
            throw new SelfSignedCACreationException("Unable to create subjectKeyPair: " + e.getMessage(), e);
        }
    }
}
