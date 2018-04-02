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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyRevokedException;
import ch.zhaw.ba.anath.pki.exceptions.RevocationNoReasonException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("tests")
@TestPropertySource(properties = {
        "ch.zhaw.ba.anath.secret-key=abcdefghijklmnopqrst1234"
})
@Transactional(transactionManager = "pkiTransactionManager")
public class RevocationServiceIT extends CertificateAuthorityInitializer {
    @Autowired
    private RevocationService revocationService;

    @Autowired
    private SigningService signingService;

    @Autowired
    private CertificateService certificateService;

    @Before
    public void setUp() throws IOException {
        initializeCa();
    }

    @Test
    public void revokeCertificate() throws IOException {
        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeCertificate(certificate.getSerial(), "test");

        final CertificateResponseDto certificateResponseDto = certificateService.getCertificate(certificate.getSerial
                ());

        assertThat(certificateResponseDto.getValidity().isRevoked(), is(true));
        assertThat(certificateResponseDto.getValidity().isExpired(), is(false));
    }

    @Test(expected = RevocationNoReasonException.class)
    public void revokeCertificateNullReason() throws IOException {
        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeCertificate(certificate.getSerial(), null);
    }

    @Test(expected = RevocationNoReasonException.class)
    public void revokeCertificateEmptyReason() throws IOException {
        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeCertificate(certificate.getSerial(), "");
    }

    @Test(expected = RevocationNoReasonException.class)
    public void revokeCertificateTestTrimmingOfReason() throws IOException {
        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeCertificate(certificate.getSerial(), "      ");
    }

    @Test(expected = CertificateAlreadyRevokedException.class)
    public void revokeRevokedCertificate() throws IOException {
        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeCertificate(certificate.getSerial(), "test");
        revocationService.revokeCertificate(certificate.getSerial(), "test");
    }
}