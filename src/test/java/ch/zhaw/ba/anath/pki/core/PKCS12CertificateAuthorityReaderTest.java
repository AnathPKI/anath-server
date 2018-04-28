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

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateAuthorityReaderException;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author Rafael Ostertag
 */
public class PKCS12CertificateAuthorityReaderTest {

    @Test(expected = CertificateAuthorityReaderException.class)
    public void certificateAuthorityEncryptedWrongPassword() throws Exception {
        try (InputStream inputStream = new FileInputStream(TestConstants.PKCS12_ENCRYPTED_FILE_NAME)) {
            new PKCS12CertificateAuthorityReader(inputStream, "wrong password");
        }
    }

    @Test
    public void certificateAuthorityEncrypted() throws Exception {
        try (InputStream inputStream = new FileInputStream(TestConstants.PKCS12_ENCRYPTED_FILE_NAME)) {
            final PKCS12CertificateAuthorityReader pkcs12CertificateAuthorityReader = new
                    PKCS12CertificateAuthorityReader(inputStream, "test1234.");

            final CertificateAuthority certificateAuthority = pkcs12CertificateAuthorityReader.certificateAuthority();
            assertNotNull(certificateAuthority);
            assertNotNull(certificateAuthority.getPrivateKey());
            assertNotNull(certificateAuthority.getCertificate());
            assertEquals(TestConstants.CA_CERT_X500_NAME, certificateAuthority.getCASubjectName());
        }
    }

    @Test
    public void certificateAuthorityEncryptedEmptyPassword() throws Exception {
        try (InputStream inputStream = new FileInputStream(TestConstants.PKCS12_ENCRYPTED_EMPTY_PASSWORD_FILE_NAME)) {
            final PKCS12CertificateAuthorityReader pkcs12CertificateAuthorityReader = new
                    PKCS12CertificateAuthorityReader(inputStream, "");

            final CertificateAuthority certificateAuthority = pkcs12CertificateAuthorityReader.certificateAuthority();
            assertNotNull(certificateAuthority);
            assertNotNull(certificateAuthority.getPrivateKey());
            assertNotNull(certificateAuthority.getCertificate());
            assertEquals(TestConstants.CA_CERT_X500_NAME, certificateAuthority.getCASubjectName());
        }
    }
}