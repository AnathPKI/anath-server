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

/**
 * Instantiates a default {@link CertificateExtensionsActions} instance.
 * <p>
 * A default {@link CertificateExtensionsActions} instance provides
 * <ul>
 * <li>{@link CaBasicConstraintExtensionProvider}</li>
 * <li>{@link CaAuthorityKeyIdentifierExtensionProvider}</li>
 * <li>{@link CaSubjectKeyIdentifierExtensionProvider}</li>
 * <li>{@link CaKeyUsageExtensionProvider}</li>
 * <li>{@link CaCertificatePoliciesExtensionProvider}</li>
 * </ul>
 *
 * @author Rafael Ostertag
 */
public class Rfc5280CAExtensionsActionsFactory implements CertificateExtensionsActionsFactoryInterface {
    public CertificateExtensionsActions getInstance() {
        final CertificateExtensionsActions certificateExtensionsActions = new CertificateExtensionsActions();
        certificateExtensionsActions.addExtensionProvider(new CaBasicConstraintExtensionProvider());
        certificateExtensionsActions.addExtensionProvider(new CaAuthorityKeyIdentifierExtensionProvider());
        certificateExtensionsActions.addExtensionProvider(new CaSubjectKeyIdentifierExtensionProvider());
        certificateExtensionsActions.addExtensionProvider(new CaKeyUsageExtensionProvider());
        certificateExtensionsActions.addExtensionProvider(new CaCertificatePoliciesExtensionProvider());

        return certificateExtensionsActions;
    }
}
