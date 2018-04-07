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

package ch.zhaw.ba.anath.pki.core.extensions;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.junit.Test;

import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

/**
 * @author Rafael Ostertag
 */
public class CertificateExtensionsActionsTest {

    @Test
    public void apply() {
        final CertificateExtensionsActions certificateExtensionsActions = new CertificateExtensionsActions();

        final CertificateAuthorityExtensionProvider extensionProviderMock1 = mock
                (CertificateAuthorityExtensionProvider.class);
        given(extensionProviderMock1.addExtension(any(), any())).will(x -> x.getArguments()[0]);
        certificateExtensionsActions.addExtensionProvider(extensionProviderMock1);

        final CertificateAuthorityExtensionProvider extensionProviderMock2 = mock
                (CertificateAuthorityExtensionProvider.class);
        given(extensionProviderMock2.addExtension(any(), any())).will(x -> x.getArguments()[0]);
        certificateExtensionsActions.addExtensionProvider(extensionProviderMock2);

        final X509v3CertificateBuilder certificateBuilderMock = mock(X509v3CertificateBuilder.class);

        final ExtensionArguments extensionArguments = new ExtensionArguments();
        certificateExtensionsActions.apply(certificateBuilderMock, extensionArguments);

        then(extensionProviderMock1).should(times(1)).addExtension(certificateBuilderMock, extensionArguments);
        then(extensionProviderMock2).should(times(1)).addExtension(certificateBuilderMock, extensionArguments);
    }
}