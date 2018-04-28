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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.TestHelper;
import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyRevokedException;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

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

    @Autowired
    private SecureStoreService secureStoreService;

    @Before
    public void setUp() throws IOException {
        initializeCa();
    }

    @Test
    public void revokeCertificate() throws IOException {
        testWhetherCrlIsEmpty();
        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeCertificate(certificate.getSerial(), "test");

        final CertificateResponseDto certificateResponseDto = certificateService.getCertificate(certificate.getSerial
                ());

        assertThat(certificateResponseDto.getValidity().getRevocationTime(), is(notNullValue()));
        assertThat(certificateResponseDto.getValidity().getRevocationReason(), is("test"));
        assertThat(certificateResponseDto.getValidity().isRevoked(), is(true));
        assertThat(certificateResponseDto.getValidity().isExpired(), is(false));

        testCrlNonEmpty();
    }

    @Test
    public void revokeCertificatesByUser() throws IOException {
        testWhetherCrlIsEmpty();

        Certificate certificate1 = TestHelper.signAndAddCertificate(signingService, "plain");

        revocationService.revokeAllCertificatesByUser("does not exist", "reason");

        final CertificateResponseDto nonRevokedCertificate = certificateService.getCertificate(certificate1.getSerial
                ());
        assertThat(nonRevokedCertificate.getValidity().isExpired(), is(false));
        assertThat(nonRevokedCertificate.getValidity().isRevoked(), is(false));

        revocationService.revokeAllCertificatesByUser(TestHelper.TEST_USER_ID, "revoked");

        final CertificateResponseDto revokedCertificate = certificateService.getCertificate(certificate1.getSerial());
        assertThat(revokedCertificate.getValidity().isRevoked(), is(true));
    }

    private void testCrlNonEmpty() {
        final String crlPemEncoded = revocationService.getCrlPemEncoded();
        assertThat(crlPemEncoded, is(notNullValue()));
    }

    private void testWhetherCrlIsEmpty() {
        try {
            revocationService.getCrlPemEncoded();
            fail("CRL already initialized");
        } catch (CertificateAuthorityNotInitializedException e) {
            // good
        }
    }

    @Test
    public void updateCertificateRevocationListEmpty() {
        testWhetherCrlIsEmpty();

        revocationService.updateCertificateRevocationList();

        testCrlNonEmpty();
    }

    @Test
    public void updateCertificateRevocationList() throws IOException {
        // Create empty crl. Take size 'n'. Sign a certificate and revoke it. Take size 'm' of crl. 'm > n' must hold.
        testWhetherCrlIsEmpty();

        // Create empty crl.
        revocationService.updateCertificateRevocationList();

        final String emptyCrl = revocationService.getCrlPemEncoded();
        final int sizeEmpty = emptyCrl.length();

        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, "plain");
        revocationService.revokeCertificate(certificate.getSerial(), "test");

        final String crlWithRevokedCertificate = revocationService.getCrlPemEncoded();
        final int sizeWithRevokedCertificate = crlWithRevokedCertificate.length();

        assertThat(sizeWithRevokedCertificate, is(greaterThan(sizeEmpty)));
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