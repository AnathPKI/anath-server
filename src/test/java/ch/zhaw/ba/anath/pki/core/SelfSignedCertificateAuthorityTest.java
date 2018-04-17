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

import ch.zhaw.ba.anath.pki.core.exceptions.SelfSignedCACreationException;
import ch.zhaw.ba.anath.pki.core.extensions.Rfc5280CAExtensionsActionsFactory;
import ch.zhaw.ba.anath.pki.core.interfaces.SecureRandomProvider;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author Rafael Ostertag
 */
public class SelfSignedCertificateAuthorityTest {

    private SelfSignedCANameBuilder caNameBuilder;
    private SelfSignedCertificateAuthority selfSignedCertificateAuthority;

    @Before
    public void setUp() {
        caNameBuilder = SelfSignedCANameBuilder.builder()
                .organization("Test CA")
                .commonName("Test CA")
                .build();
        selfSignedCertificateAuthority = new SelfSignedCertificateAuthority(
                caNameBuilder,
                new OneYearValidity(),
                new UuidCertificateSerialProvider(),
                new SecureRandomProviderImpl(),
                new Sha512WithRsa(),
                new Rfc5280CAExtensionsActionsFactory(), 2048);
    }

    @Test
    public void getCertificateAuthority() {
        // The test is to directly call #getCertificate() without first calling #create().
        final CertificateAuthority certificateAuthority = selfSignedCertificateAuthority.getCertificateAuthority();
        assertNotNull(certificateAuthority.getCertificate());
        assertEquals(certificateAuthority.getCASubjectName(), caNameBuilder.toX500Name());
        assertEquals(certificateAuthority.getCertificate().getSubject(), caNameBuilder.toX500Name());
        assertEquals(certificateAuthority.getCertificate().getCertificateHolder().getIssuer(), caNameBuilder
                .toX500Name());
        assertNotNull(certificateAuthority.getCertificate());
    }

    @Test
    public void create() {
        selfSignedCertificateAuthority.create();
        final CertificateAuthority certificateAuthority = selfSignedCertificateAuthority.getCertificateAuthority();
        assertNotNull(certificateAuthority.getCertificate());
        assertEquals(certificateAuthority.getCertificate().getSubject(), caNameBuilder.toX500Name());
        assertEquals(certificateAuthority.getCASubjectName(), caNameBuilder.toX500Name());
        assertEquals(certificateAuthority.getCertificate().getCertificateHolder().getIssuer(), caNameBuilder
                .toX500Name());
        assertNotNull(certificateAuthority.getPrivateKey());
    }

    @Test(expected = SelfSignedCACreationException.class)
    public void keyBitSizeBelow1024() {
        new SelfSignedCertificateAuthority(null, null, null, null, null, new Rfc5280CAExtensionsActionsFactory(), 512);
    }

    @Test(expected = SelfSignedCACreationException.class)
    public void keyBitSizeNotInList() {
        new SelfSignedCertificateAuthority(null, null, null, null, null, new Rfc5280CAExtensionsActionsFactory(), 1025);
    }

    @Test
    public void keyBitSize1024() {
        // Not throwing an exception is the test
        new SelfSignedCertificateAuthority(
                caNameBuilder,
                new OneYearValidity(),
                new UuidCertificateSerialProvider(),
                new TestNonBlockingSecureRandomProvider(),
                new Sha512WithRsa(),
                new Rfc5280CAExtensionsActionsFactory(), 1024);
    }

    @Test
    public void testSelfSignedCaWithOpenSSL() throws Exception {
        final File caKeyFile = File.createTempFile("caKey", null);
        final File caCertificateFile = File.createTempFile("caFile", null);
        selfSignedCertificateAuthority.create();
        try (
                OutputStreamWriter caKeyWriter = new OutputStreamWriter(new FileOutputStream(caKeyFile));
                OutputStreamWriter caCertificateWriter = new OutputStreamWriter(new FileOutputStream
                        (caCertificateFile))
        ) {
            selfSignedCertificateAuthority.create();
            final PEMCertificateAuthorityWriter pemCertificateAuthorityWriter = new PEMCertificateAuthorityWriter(new
                    PEMCertificateWriter(caCertificateWriter), new
                    PEMPrivateKeyWriter(caKeyWriter));

            pemCertificateAuthorityWriter.writeCA(selfSignedCertificateAuthority.getCertificateAuthority());

            final Process exec = Runtime.getRuntime().exec(
                    new String[]{
                            "openssl",
                            "verify",
                            "-CAfile",
                            caCertificateFile.getAbsolutePath(),
                            caCertificateFile.getAbsolutePath()
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
        } finally {
            caCertificateFile.delete();
            caKeyFile.delete();
        }
    }

    @Slf4j
    public class TestNonBlockingSecureRandomProvider implements SecureRandomProvider {

        @Override
        public SecureRandom getSecureRandom() {
            try {
                log.warn("USE TEST INSECURE PRNG");
                return SecureRandom.getInstance("NATIVEPRNGNONBLOCKING");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }
}