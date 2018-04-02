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
import ch.zhaw.ba.anath.pki.core.PEMCertificateWriter;
import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.dto.UseDto;
import ch.zhaw.ba.anath.pki.dto.bits.CertificateValidityBit;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.util.Base64;
import java.util.List;

import static org.hamcrest.Matchers.*;
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
public class CertificateServiceIT extends CertificateAuthorityInitializer {
    private static final String TEST_USE = "test.use";
    @PersistenceContext(unitName = "pki")
    private EntityManager entityManager;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private UseService useService;

    @Autowired
    private SigningService signingService;

    @Before
    public void setUp() throws IOException {
        initializeCa();
    }

    private Certificate signAndAddCertificate() throws IOException {
        return TestHelper.signAndAddCertificate(signingService, UseEntity.DEFAULT_USE);
    }

    @Test
    public void getCertificate() throws IOException {
        final Certificate certificate = signAndAddCertificate();
        final CertificateResponseDto certificateResponseDto = certificateService.getCertificate(certificate.getSerial
                ());

        final String certificateString = certificateToPemString(certificate);
        assertThat(certificateResponseDto.getCert().getPem(), is(certificateString));
        assertThat(certificateResponseDto.getUse(), is("plain"));
        final CertificateValidityBit validity = certificateResponseDto.getValidity();
        assertThat(validity.getRevocationReason(), is(nullValue()));
        assertThat(validity.getRevocationTime(), is(nullValue()));
        assertThat(validity.getNotAfter().getTime(), is(equalTo(certificate.getValidTo().getTime())));
        assertThat(validity.getNotBefore().getTime(), is(equalTo(certificate.getValidFrom().getTime())));
        assertThat(validity.isExpired(), is(false));
        assertThat(validity.isRevoked(), is(false));
    }

    @Test(expected = CertificateNotFoundException.class)
    public void getCertificateNonExisting() {
        certificateService.getCertificate(BigInteger.TEN);
    }

    private String certificateToPemString(Certificate certificate) {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final PEMCertificateWriter pemCertificateWriter = new PEMCertificateWriter(new OutputStreamWriter
                (byteArrayOutputStream));
        pemCertificateWriter.writeCertificate(certificate);
        return byteArrayOutputStream.toString();
    }

    @Test
    public void getPlainPEMEncodedCertificate() throws IOException {
        final Certificate certificate = signAndAddCertificate();
        final String actual = certificateService.getPlainPEMEncodedCertificate(certificate.getSerial());

        final String expected = certificateToPemString(certificate);
        assertThat(actual, is(expected));
    }

    @Test(expected = CertificateNotFoundException.class)
    public void getNonExistingPlainPEMEncodedCertificate() {
        certificateService.getPlainPEMEncodedCertificate(BigInteger.TEN);
    }

    @Test
    public void getAll() throws IOException {
        final Certificate certificate = signAndAddCertificate();
        final List<CertificateListItemDto> all = certificateService.getAll();
        assertThat(all, hasSize(1));

        final CertificateListItemDto certificateListItemDto = all.get(0);
        assertThat(certificateListItemDto.getSerial(), is(certificate.getSerial()));
        assertThat(certificateListItemDto.getSubject(), is(certificate.getSubject().toString()));
        assertThat(certificateListItemDto.getUse(), is("plain"));
    }

    @Test
    public void getAllEmpty() {
        final List<CertificateListItemDto> all = certificateService.getAll();
        assertThat(all, is(empty()));
    }

    @Test
    public void testWithConfiguration() throws IOException {
        final UseDto useDto = new UseDto();
        useDto.setConfiguration("${caCertificate} ${userCertificate}");
        useDto.setUse(TEST_USE);

        useService.create(useDto);

        final Certificate certificate = TestHelper.signAndAddCertificate(signingService, TEST_USE);

        final CertificateResponseDto certificateResponseDto = certificateService.getCertificate(certificate.getSerial
                ());

        assertThat(certificateResponseDto.getConfig(), is(notNullValue()));
        final byte[] decodedConfiguration = Base64.getDecoder().decode(certificateResponseDto.getConfig());
        final String configuration = new String(decodedConfiguration);

        assertThat(configuration, containsString("-----BEGIN CERTIFICATE-----"));
        assertThat(configuration, containsString("-----END CERTIFICATE-----"));

        final String certificateString = certificateToPemString(certificate);
        assertThat(certificateResponseDto.getCert().getPem(), is(certificateString));
        assertThat(certificateResponseDto.getUse(), is(TEST_USE));

        final CertificateValidityBit validity = certificateResponseDto.getValidity();
        assertThat(validity.getRevocationReason(), is(nullValue()));
        assertThat(validity.getRevocationTime(), is(nullValue()));
        assertThat(validity.getNotAfter().getTime(), is(equalTo(certificate.getValidTo().getTime())));
        assertThat(validity.getNotBefore().getTime(), is(equalTo(certificate.getValidFrom().getTime())));
        assertThat(validity.isExpired(), is(false));
        assertThat(validity.isRevoked(), is(false));
    }
}