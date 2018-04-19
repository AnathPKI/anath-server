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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;

/**
 * @author Rafael Ostertag
 */
public class CertificateRevocationListCreatorTest {

    public static final long ARBITRARY_DATE_IN_MILLIS = 100000000L;
    private static final long TEN_SECONDS_IN_MILLIS = 10 * 1000L;
    private File crlFile;

    @Before
    public void setUp() throws IOException {
        crlFile = File.createTempFile("crl", null);
    }

    @After
    public void tearDown() {
        if (crlFile != null) {
            crlFile.delete();
        }
    }

    @Test
    public void create() throws IOException, InterruptedException {
        final Certificate certificate = readCertificate();

        final Date revocationDate = new Date(ARBITRARY_DATE_IN_MILLIS);
        final RevokedCertificate revokedCertificate = new RevokedCertificate(certificate, revocationDate);

        final List<RevokedCertificate> revokedCertificates = new ArrayList<>();
        revokedCertificates.add(revokedCertificate);

        final CertificateAuthority certificateAuthority = readCertificateAuthority();
        final CertificateRevocationListCreator certificateRevocationListCreator =
                createCertificateRevocationListCreater(certificateAuthority);

        final CertificateRevocationList certificateRevocationList = certificateRevocationListCreator.create
                (revokedCertificates);

        assertEquals(certificateRevocationList.getIssuer(), certificateAuthority.getCASubjectName());
        assertThat(certificateRevocationList.getNextUpdate().after(new Date()), is(true));
        assertThat(certificateRevocationList.getThisUpdate().before(new Date()), is(true));

        try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(new FileOutputStream(crlFile))) {
            final PEMCertificateRevocationListWriter pemCertificateRevocationListWriter = new
                    PEMCertificateRevocationListWriter(outputStreamWriter);

            pemCertificateRevocationListWriter.writeRevocationList(certificateRevocationList);
        }

        testCrlFileWithOpenSsl(crlFile);
    }

    @Test
    public void createEmptyList() throws IOException, InterruptedException {
        final List<RevokedCertificate> revokedCertificates = new ArrayList<>();

        final CertificateAuthority certificateAuthority = readCertificateAuthority();
        final CertificateRevocationListCreator certificateRevocationListCreator =
                createCertificateRevocationListCreater(certificateAuthority);

        final Date nextUpdate = new Date(ARBITRARY_DATE_IN_MILLIS + ARBITRARY_DATE_IN_MILLIS);
        // Used later to compare to thisUpdate.
        final Date now = new Date();
        final CertificateRevocationList certificateRevocationList = certificateRevocationListCreator.create
                (revokedCertificates);

        assertEquals(certificateRevocationList.getIssuer(), certificateAuthority.getCASubjectName());
        assertThat(certificateRevocationList.getNextUpdate().after(new Date()), is(true));
        assertThat(certificateRevocationList.getThisUpdate().before(new Date()), is(true));

        try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(new FileOutputStream(crlFile))) {
            final PEMCertificateRevocationListWriter pemCertificateRevocationListWriter = new
                    PEMCertificateRevocationListWriter(outputStreamWriter);

            pemCertificateRevocationListWriter.writeRevocationList(certificateRevocationList);
        }

        testCrlFileWithOpenSsl(crlFile);
    }

    private void testCrlFileWithOpenSsl(File crlFile) throws IOException, InterruptedException {
        final Process exec = Runtime.getRuntime().exec(
                new String[]{
                        "openssl",
                        "crl",
                        "-verify",
                        "-noout",
                        "-in",
                        crlFile.getAbsolutePath(),
                        "-CAfile",
                        TestConstants.CA_CERT_FILE_NAME
                }
        );

        final int returnValue = exec.waitFor();
        try (InputStream errorStream = exec.getErrorStream();
             InputStream stdoutStream = exec.getInputStream()) {
            int b;
            while ((b = errorStream.read()) != -1) {
                System.out.print((char) b);
            }

            while ((b = stdoutStream.read()) != -1) {
                System.out.print((char) b);
            }
        }

        assertEquals(0, returnValue);
    }

    private CertificateRevocationListCreator createCertificateRevocationListCreater(CertificateAuthority
                                                                                            certificateAuthority) {
        return
                new CertificateRevocationListCreator(
                        new Sha512WithRsa(),
                        certificateAuthority, new ConfigurablePeriodCRLValidity(2));
    }

    private CertificateAuthority readCertificateAuthority() throws IOException {

        try (
                InputStreamReader caKey = new InputStreamReader(new FileInputStream(TestConstants.CA_KEY_FILE_NAME));
                InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_CERT_FILE_NAME))
        ) {
            final PEMCertificateAuthorityReader pemCertificateAuthorityReader = new PEMCertificateAuthorityReader
                    (caKey, caCert);
            return pemCertificateAuthorityReader.certificateAuthority();
        }
    }

    private Certificate readCertificate() throws IOException {
        try (InputStreamReader caCert = new InputStreamReader(new FileInputStream(TestConstants.CA_CERT_FILE_NAME))) {
            final PEMCertificateReader pemCertificateReader = new PEMCertificateReader(caCert);
            return pemCertificateReader.certificate();
        }
    }
}