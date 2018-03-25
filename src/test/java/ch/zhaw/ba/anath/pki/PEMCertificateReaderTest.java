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

package ch.zhaw.ba.anath.pki;

import ch.zhaw.ba.anath.pki.exceptions.CertificateReaderException;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author Rafael Ostertag
 */
public class PEMCertificateReaderTest {

    @Test
    public void certificate() throws Exception {
        try (InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_CERT_FILE_NAME))) {
            final PEMCertificateReader pemCertificateReader = new PEMCertificateReader(caCert);
            final Certificate certificate = pemCertificateReader.certificate();

            assertNotNull(certificate);
            assertNotNull(certificate.getCertificateHolder());

            assertEquals(TestConstants.CA_CERT_X500_NAME, certificate.getSubject());
            assertEquals(TestConstants.CA_CERT_SERIAL, certificate.getSerial());
            assertEquals(new Date(1519497897000L), certificate.getValidFrom());
            assertEquals(new Date(1551033897000L), certificate.getValidTo());
        }
    }

    @Test(expected = CertificateReaderException.class)
    public void invalidCertificate() throws Exception {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(TestConstants.INVALID_CA_CERT
                .getBytes());
        try (InputStreamReader caCert = new InputStreamReader(byteArrayInputStream)) {
            new PEMCertificateReader(caCert);
        }
    }

    @Test(expected = CertificateReaderException.class)
    public void readKeyAsCert() throws Exception {
        try (InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_KEY_FILE_NAME))) {
            new PEMCertificateReader(caCert);
        }
    }
}