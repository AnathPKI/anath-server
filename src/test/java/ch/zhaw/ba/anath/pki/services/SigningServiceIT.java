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
import ch.zhaw.ba.anath.pki.core.CertificateSigningRequest;
import ch.zhaw.ba.anath.pki.core.PEMCertificateSigningRequestReader;
import ch.zhaw.ba.anath.pki.core.TestConstants;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyExistsException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.repositories.UseRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * {@link SigningService} caches the CA. Tests requiring a non-initialized CA cannot be run in here.
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("tests")
@TestPropertySource(properties = {
        "ch.zhaw.ba.anath.secret-key=abcdefghijklmnopqrst1234"
})
@Transactional(transactionManager = "pkiTransactionManager")
public class SigningServiceIT extends CertificateAuthorityInitializer {
    public static final String TEST_CERTIFIACTE_USE_NAME = "test use";

    @Autowired
    private SigningService signingService;

    @Autowired
    private UseRepository useRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Before
    public void setUp() throws IOException {
        initializeCa();
    }

    @Test
    public void sign() throws Exception {
        final Certificate certificate;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            certificate = signingService.signCertificate(certificateSigningRequest, "test id",
                    UseEntity.DEFAULT_USE);
        }
        assertThat(certificate, is(notNullValue()));

        flushAndClear();

        Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(certificate
                .getSerial());
        assertThat(optionalCertificateEntity.isPresent(), is(true));

        final CertificateEntity certificateEntity = optionalCertificateEntity.get();
        assertThat(certificateEntity.getStatus(), is(CertificateStatus.VALID));
        assertThat(certificateEntity.getUserId(), is(equalTo("test id")));
        assertThat(certificateEntity.getNotValidAfter().getTime(), is(equalTo(certificate.getValidTo().getTime())));
        assertThat(certificateEntity.getNotValidBefore().getTime(), is(equalTo(certificate.getValidFrom().getTime())));
        assertThat(certificateEntity.getSubject(), is(equalTo(certificate.getSubject().toString())));

        final UseEntity useEntity = certificateEntity.getUse();
        assertThat(useEntity, is(not(nullValue())));
        assertThat(useEntity.getUse(), is(UseEntity.DEFAULT_USE));
    }

    @Test
    public void signCertificateWithSameRevoked() throws Exception {
        final Certificate certificateToBeRevoked;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            certificateToBeRevoked = signingService.signCertificate(certificateSigningRequest, "test id",
                    UseEntity.DEFAULT_USE);
        }
        assertThat(certificateToBeRevoked, is(notNullValue()));

        // We revoke the currently signed certificate
        final Optional<CertificateEntity> currentActive = certificateRepository.findOneBySerial(certificateToBeRevoked
                .getSerial());
        final CertificateEntity certificateEntityToBeRevoked = currentActive.get();
        certificateEntityToBeRevoked.setStatus(CertificateStatus.REVOKED);
        certificateRepository.save(certificateEntityToBeRevoked);

        flushAndClear();

        // And sign it again
        final Certificate certificate;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            certificate = signingService.signCertificate(certificateSigningRequest, "test id",
                    UseEntity.DEFAULT_USE);
        }
        assertThat(certificate, is(notNullValue()));

        flushAndClear();

        Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(certificate
                .getSerial());
        assertThat(optionalCertificateEntity.isPresent(), is(true));

        final CertificateEntity certificateEntity = optionalCertificateEntity.get();
        assertThat(certificateEntity.getStatus(), is(CertificateStatus.VALID));
        assertThat(certificateEntity.getUserId(), is(equalTo("test id")));
        assertThat(certificateEntity.getNotValidAfter().getTime(), is(equalTo(certificate.getValidTo().getTime())));
        assertThat(certificateEntity.getNotValidBefore().getTime(), is(equalTo(certificate.getValidFrom().getTime())));
        assertThat(certificateEntity.getSubject(), is(equalTo(certificate.getSubject().toString())));

        final UseEntity useEntity = certificateEntity.getUse();
        assertThat(useEntity, is(not(nullValue())));
        assertThat(useEntity.getUse(), is(UseEntity.DEFAULT_USE));
    }

    @Test
    public void signWithNonExistingUse() throws Exception {
        final Certificate certificate;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            certificate = signingService.signCertificate(certificateSigningRequest, "test id",
                    "does not exist");
        }
        assertThat(certificate, is(notNullValue()));

        flushAndClear();

        Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(certificate
                .getSerial());
        assertThat(optionalCertificateEntity.isPresent(), is(true));

        final CertificateEntity certificateEntity = optionalCertificateEntity.get();
        final UseEntity useEntity = certificateEntity.getUse();
        assertThat(useEntity, is(not(nullValue())));
        assertThat(useEntity.getUse(), is(UseEntity.DEFAULT_USE));
    }

    @Test
    public void signWithNonDefaultUse() throws Exception {
        final UseEntity testUseEntity = new UseEntity();
        testUseEntity.setUse(TEST_CERTIFIACTE_USE_NAME);
        testUseEntity.setConfig(null);

        useRepository.save(testUseEntity);

        flushAndClear();

        final Certificate certificate;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            certificate = signingService.signCertificate(certificateSigningRequest, "test id",
                    TEST_CERTIFIACTE_USE_NAME);
        }
        assertThat(certificate, is(notNullValue()));

        flushAndClear();

        Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(certificate
                .getSerial());
        assertThat(optionalCertificateEntity.isPresent(), is(true));

        final CertificateEntity certificateEntity = optionalCertificateEntity.get();
        final UseEntity useEntity = certificateEntity.getUse();
        assertThat(useEntity, is(not(nullValue())));
        assertThat(useEntity.getUse(), is(TEST_CERTIFIACTE_USE_NAME));
    }

    @Test(expected = CertificateAlreadyExistsException.class)
    public void signSameCSRTwice() throws Exception {
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            signingService.signCertificate(certificateSigningRequest, "test id", UseEntity
                    .DEFAULT_USE);
        }

        flushAndClear();

        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(csr);
            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();
            signingService.signCertificate(certificateSigningRequest, "test id", UseEntity
                    .DEFAULT_USE);
        }

        flushAndClear();
    }
}