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

import ch.zhaw.ba.anath.pki.core.exceptions.CertificateConstraintException;
import org.junit.Test;

import java.io.*;
import java.util.Date;

import static junit.framework.TestCase.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;

/**
 * @author Rafael Ostertag
 */
public class CertificateSignerTest {

    @Test
    public void signCertificate() throws IOException {
        try (
                InputStreamReader caKey = new InputStreamReader(new FileInputStream(TestConstants.CA_KEY_FILE_NAME));
                InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_CERT_FILE_NAME));
                InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))
        ) {
            final PEMCertificateAuthorityReader pemCertificateAuthorityReader = new PEMCertificateAuthorityReader(
                    caKey,
                    caCert
            );

            final CertificateSigner certificateSigner = new CertificateSigner(new Sha512WithRsa(),
                    pemCertificateAuthorityReader.certificateAuthority());

            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader =
                    new PEMCertificateSigningRequestReader(csr);
            final Certificate certificate = certificateSigner.signCertificate
                    (pemCertificateSigningRequestReader);

            assertThat(certificate, is(not(nullValue())));
            assertThat(certificate.getCertificateHolder(), is(notNullValue()));
            assertThat(certificate.getSerial(), is(notNullValue()));
            assertThat(certificate.getValidFrom(), is(notNullValue()));
            assertThat(certificate.getValidTo().getTime(), is(greaterThan((new Date()).getTime())));
            assertThat(certificate.getSubject(), is(notNullValue()));
        }
    }

    @Test(expected = CertificateConstraintException.class)
    public void signNonMatchingOrganizationCertificate() throws IOException {
        try (
                InputStreamReader caKey = new InputStreamReader(new FileInputStream(TestConstants.CA_KEY_FILE_NAME));
                InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_CERT_FILE_NAME));
                InputStreamReader csr = new InputStreamReader(new FileInputStream(
                        TestConstants.CLIENT_CSR_NON_MATCHING_ORG_FILE_NAME))
        ) {
            final PEMCertificateAuthorityReader pemCertificateAuthorityReader = new PEMCertificateAuthorityReader
                    (caKey, caCert);
            final CertificateSigner certificateSigner = new CertificateSigner(new Sha512WithRsa(),
                    pemCertificateAuthorityReader.certificateAuthority());

            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);

            certificateSigner.signCertificate(pemCertificateSigningRequestReader);
        }
    }

    @Test
    public void saveSignedCertificate() throws Exception {
        final File certificateFile = new File("/tmp/signed.crt");
        try (
                InputStreamReader caKey = new InputStreamReader(new FileInputStream(TestConstants.CA_KEY_FILE_NAME));
                InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_CERT_FILE_NAME));
                InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME));
                OutputStreamWriter signedCert = new OutputStreamWriter(new FileOutputStream(certificateFile))
        ) {
            final PEMCertificateAuthorityReader pemCertificateAuthorityReader = new PEMCertificateAuthorityReader
                    (caKey, caCert);
            final CertificateSigner certificateSigner = new CertificateSigner(new Sha512WithRsa(),
                    pemCertificateAuthorityReader.certificateAuthority());

            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final Certificate certificate = certificateSigner.signCertificate
                    (pemCertificateSigningRequestReader);

            final PEMCertificateWriter pemCertificateWriter = new PEMCertificateWriter(signedCert);
            pemCertificateWriter.writeCertificate(certificate);

            assertTrue(certificateFile.exists());
        }
    }
}