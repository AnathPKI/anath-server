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

import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.util.LinkedList;
import java.util.List;

/**
 * Hold a list of {@link CertificateAuthorityExtensionProvider} and apply to a {@link X509v3CertificateBuilder}
 * instance.
 *
 * @author Rafael Ostertag
 */
public class CertificateExtensionsActions {
    private final List<CertificateAuthorityExtensionProvider> certificateAuthorityExtensionProviders;

    public CertificateExtensionsActions() {
        // linked list should perform reasonably well, no indexed access is required
        certificateAuthorityExtensionProviders = new LinkedList<>();
    }

    /**
     * Add a new {@link CertificateAuthorityExtensionProvider} to the list of
     * {@link CertificateAuthorityExtensionProvider}s.
     *
     * @param certificateAuthorityExtensionProvider {@link CertificateAuthorityExtensionProvider} to be added
     */
    public void addExtensionProvider(CertificateAuthorityExtensionProvider certificateAuthorityExtensionProvider) {
        certificateAuthorityExtensionProviders.add(certificateAuthorityExtensionProvider);
    }

    /**
     * Apply all {@link CertificateAuthorityExtensionProvider} to a given {@link X509v3CertificateBuilder}.
     *
     * @param certificateBuilder {@link X509v3CertificateBuilder} instance
     * @param extensionArguments {@link ExtensionArguments} instance.
     *
     * @return {@link X509v3CertificateBuilder} instance
     */
    public X509v3CertificateBuilder apply(X509v3CertificateBuilder certificateBuilder, ExtensionArguments
            extensionArguments) {
        certificateAuthorityExtensionProviders.stream().forEach(x -> x.addExtension(certificateBuilder,
                extensionArguments));
        return certificateBuilder;
    }
}
