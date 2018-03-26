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
import ch.zhaw.ba.anath.pki.core.PEMCertificateSigningRequestReader;
import ch.zhaw.ba.anath.pki.core.TestConstants;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceException;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@TestPropertySource(properties = {
        "ch.zhaw.ba.anath.secret-key=abcdefghijklmnopqrst1234"
})
@Transactional(transactionManager = "pkiTransactionManager")
public class SigningServiceIT {
    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    private SigningService signingService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private SecureStoreService secureStoreService;

    @Before
    public void setUp() throws Exception {
        try (
                InputStream certificateInputStream = new FileInputStream(TestConstants.CA_CERT_FILE_NAME);
                InputStream privateKeyInputStream = new FileInputStream(TestConstants.CA_KEY_FILE_NAME)
        ) {
            final byte[] certificate = IOUtils.toByteArray(certificateInputStream);
            secureStoreService.put(SigningService.SECURE_STORE_CA_CERTIFICATE, certificate);

            final byte[] privateKey = IOUtils.toByteArray(privateKeyInputStream);
            secureStoreService.put(SigningService.SECURE_STORE_CA_PRIVATE_KEY, privateKey);
        }
    }

    @Test
    public void sign() throws Exception {
        final Certificate certificate;
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            certificate = signingService.signCertificate(new PEMCertificateSigningRequestReader(csr), "test id");
        }
        assertThat(certificate, is(notNullValue()));

        entityManager.flush();
        entityManager.clear();

        Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(certificate
                .getSerial());
        assertThat(optionalCertificateEntity.isPresent(), is(true));

        final CertificateEntity certificateEntity = optionalCertificateEntity.get();
        assertThat(certificateEntity.getStatus(), is(CertificateStatus.VALID));
        assertThat(certificateEntity.getUserId(), is(equalTo("test id")));
        assertThat(certificateEntity.getNotValidAfter().getTime(), is(equalTo(certificate.getValidTo().getTime())));
        assertThat(certificateEntity.getNotValidBefore().getTime(), is(equalTo(certificate.getValidFrom().getTime())));
        assertThat(certificateEntity.getSubject(), is(equalTo(certificate.getSubject().toString())));
    }

    @Test(expected = PersistenceException.class)
    public void signSameCSRTwice() throws Exception {
        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            signingService.signCertificate(new PEMCertificateSigningRequestReader(csr), "test id");

        }

        entityManager.flush();
        entityManager.clear();

        try (InputStreamReader csr = new InputStreamReader(new FileInputStream(TestConstants.CLIENT_CSR_FILE_NAME))) {
            signingService.signCertificate(new PEMCertificateSigningRequestReader(csr), "test id");
        }

        entityManager.flush();
        entityManager.clear();
    }
}