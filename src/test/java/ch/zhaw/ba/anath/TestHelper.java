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

package ch.zhaw.ba.anath;

import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.core.CertificateSigningRequest;
import ch.zhaw.ba.anath.pki.core.PEMCertificateSigningRequestReader;
import ch.zhaw.ba.anath.pki.core.TestConstants;
import ch.zhaw.ba.anath.pki.services.SigningService;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Timestamp;

/**
 * @author Rafael Ostertag
 */
public final class TestHelper {

    public static final String TEST_USER_ID = "test id";
    private static final long TEN_SECONDS_IN_MILLIS = 10000L;

    private TestHelper() {
        // intentionally empty
    }

    public static Certificate signAndAddCertificate(SigningService signingService, String use) throws IOException {
        final Certificate certificate;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            String token = signingService.tentativelySignCertificate(certificateSigningRequest, TEST_USER_ID,
                    use);
            certificate = signingService.confirmTentativelySignedCertificate(token, TEST_USER_ID);
        }
        return certificate;
    }

    public static Timestamp timeEvenMoreInPast() {
        return new Timestamp(System.currentTimeMillis() - TEN_SECONDS_IN_MILLIS - TEN_SECONDS_IN_MILLIS);
    }

    public static Timestamp timeEvenFurtherInFuture() {
        return new Timestamp(System.currentTimeMillis() + TEN_SECONDS_IN_MILLIS + TEN_SECONDS_IN_MILLIS);
    }

    public static Timestamp timeInPast() {
        return new Timestamp(System.currentTimeMillis() - TEN_SECONDS_IN_MILLIS);
    }

    public static Timestamp timeInFuture() {
        return new Timestamp(System.currentTimeMillis() + TEN_SECONDS_IN_MILLIS);
    }
}
