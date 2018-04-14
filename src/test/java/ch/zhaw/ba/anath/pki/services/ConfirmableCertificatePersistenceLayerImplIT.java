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

import ch.zhaw.ba.anath.pki.core.exceptions.PKIException;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.UseRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.concurrent.TimeUnit;

import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles({"confirm", "tests"})
@TestPropertySource(properties = {
        "ch.zhaw.ba.anath.secret-key=abcdefghijklmnopqrst1234"
})
@Transactional(transactionManager = "pkiTransactionManager")
public class ConfirmableCertificatePersistenceLayerImplIT {
    // The exact content is not important, but it must be a valid X.509 PEM encoded certificate.
    private static final String TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
            "MIID/jCCAuagAwIBAgIJAPQj6jMYDszkMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYD\n" +
            "VQQGEwJDSDEQMA4GA1UECAwHVGh1cmdhdTEQMA4GA1UEBwwHS2VmaWtvbjEYMBYG\n" +
            "A1UECgwPUmFmYWVsIE9zdGVydGFnMQwwCgYDVQQLDANkZXYxGDAWBgNVBAMMD1Jh\n" +
            "ZmFlbCBPc3RlcnRhZzEeMBwGCSqGSIb3DQEJARYPcmFmaUBndWVuZ2VsLmNoMB4X\n" +
            "DTE4MDIyNDE4NDQ1N1oXDTE5MDIyNDE4NDQ1N1owgZMxCzAJBgNVBAYTAkNIMRAw\n" +
            "DgYDVQQIDAdUaHVyZ2F1MRAwDgYDVQQHDAdLZWZpa29uMRgwFgYDVQQKDA9SYWZh\n" +
            "ZWwgT3N0ZXJ0YWcxDDAKBgNVBAsMA2RldjEYMBYGA1UEAwwPUmFmYWVsIE9zdGVy\n" +
            "dGFnMR4wHAYJKoZIhvcNAQkBFg9yYWZpQGd1ZW5nZWwuY2gwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDe9/4o6/YCQ7h3uuepDzJOGu7YmSFjJJ8hE6BH\n" +
            "SckqaNLaqHkSvKmTzPt+CG2ZDaHeH6WhCfUWf8VL8gwt4QCEAjsM8Zs82+BT1HRg\n" +
            "tkaCaBeugLVWreG34clHcBnJgzoCRHFS92WXm16EmLU3ZVCy5ySgrDF0yNfPPWkr\n" +
            "hDFEtqIZ11t2pLNcdUsVnmP+68FEEo0B5zriUcbXUzE9NZLOzyaTWyWr/iipmBxv\n" +
            "D9BSQVx1NP3q3SBkDvNQIagjTxJtSg3ZYm2uzxUkOfSNsIC4yk35ySUL7470WCkF\n" +
            "MQQW4ZCE+KmvlmE+FfD7XIAVOYb7k2uPmO44AclQGjdxMNfZAgMBAAGjUzBRMB0G\n" +
            "A1UdDgQWBBQnZHOL8Uz4l8XpNZ0x/n2QJpTYyzAfBgNVHSMEGDAWgBQnZHOL8Uz4\n" +
            "l8XpNZ0x/n2QJpTYyzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCrNT5IwcDNWkdkvnGZzDIPqNvd5Sr/WQeRRCUJ8tM1wYRP+/beilekmaWl3mAl\n" +
            "0x5zGwUxBSgGv45q6j9FJu9rbwgk2x8/rVWycUCdGQJDzciGKUycE9bA4W8nV9dE\n" +
            "89nXXIo6aB2CC6+jiILTEHIiLoSIUeJTECe1tGh+fW4K7zdbVvmgxwEmP5oGwy13\n" +
            "uKpMYjUOaKZGgIjlN5+q+YCZIcwnC+iNma3/re3iNPyyRz5eX5/8h07R7EhL4bvr\n" +
            "ZDg7YsEg4AwLsuuIEz1W3ff+OQu6O4/Qe1PTc+/TDJgKd8wq5Nc1oOIMI6J8Ij21\n" +
            "3Pdg9DnfsOnW5/jb/3/ix9zA\n" +
            "-----END CERTIFICATE-----\n";
    private static final BigInteger TEST_CERTIFICATE_SERIAL = BigInteger.TEN;
    private static final String TEST_CERTIFICATE_SUBJECT = "test subject";
    private static final String TEST_USER_ID = "test user id";
    private static final Timestamp TEST_NOT_VALID_BEFORE = new Timestamp(1000000000L);
    private static final Timestamp TEST_NOT_VALID_AFTER = new Timestamp(9000000000L);
    private static final String TEST_USE = "plain";

    @PersistenceContext(unitName = "pki")
    private EntityManager entityManager;

    @Autowired
    private ConfirmableCertificatePersistenceLayer confirmableCertificatePersistenceLayer;

    @Autowired
    private UseRepository useRepository;

    @MockBean
    private RedisTemplate<ConfirmationKey, CertificateEntity> redisTemplate;
    private ValueOperations opsForValueMock;

    @Before
    public void setUp() {
        this.opsForValueMock = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(opsForValueMock);
    }

    @Test
    public void store() {
        final CertificateEntity certificateEntity = makeTestCertificateEntity();
        final String confirmationToken = confirmableCertificatePersistenceLayer.store(certificateEntity);

        final ConfirmationKey expectedConfirmationKey = new ConfirmationKey(confirmationToken, TEST_USER_ID);
        then(opsForValueMock).should().set(expectedConfirmationKey, certificateEntity, 60, TimeUnit.MINUTES);

        given(opsForValueMock.get(expectedConfirmationKey)).willReturn(certificateEntity);

        final CertificateEntity confirm = confirmableCertificatePersistenceLayer.confirm(confirmationToken,
                TEST_USER_ID);
        then(redisTemplate).should().delete(expectedConfirmationKey);
        entityManager.flush();
    }

    @Test
    public void storeWithNonExistingUse() {
        final CertificateEntity certificateEntity = makeTestCertificateEntity();
        certificateEntity.getUse().setUse("does not exist");
        final String confirmationToken = confirmableCertificatePersistenceLayer.store(certificateEntity);

        final ConfirmationKey expectedConfirmationKey = new ConfirmationKey(confirmationToken, TEST_USER_ID);
        then(opsForValueMock).should().set(expectedConfirmationKey, certificateEntity, 60, TimeUnit.MINUTES);

        given(opsForValueMock.get(expectedConfirmationKey)).willReturn(certificateEntity);

        final CertificateEntity confirm = confirmableCertificatePersistenceLayer.confirm(confirmationToken,
                TEST_USER_ID);
        then(redisTemplate).should().delete(expectedConfirmationKey);
        entityManager.flush();
    }

    @Test(expected = PKIException.class)
    public void storeWithNonExistingUseAndNoDefaultUseExisting() {
        // Drop the default use 'plain', the code must panic and throw an exception when no default use is found.
        useRepository.deleteByUse("plain");
        entityManager.flush();

        // Play the process
        final CertificateEntity certificateEntity = makeTestCertificateEntity();
        certificateEntity.getUse().setUse("does not exist");
        final String confirmationToken = confirmableCertificatePersistenceLayer.store(certificateEntity);

        final ConfirmationKey expectedConfirmationKey = new ConfirmationKey(confirmationToken, TEST_USER_ID);
        then(opsForValueMock).should().set(expectedConfirmationKey, certificateEntity, 60, TimeUnit.MINUTES);

        given(opsForValueMock.get(expectedConfirmationKey)).willReturn(certificateEntity);

        final CertificateEntity confirm = confirmableCertificatePersistenceLayer.confirm(confirmationToken,
                TEST_USER_ID);
        then(redisTemplate).should().delete(expectedConfirmationKey);
        entityManager.flush();
    }

    private CertificateEntity makeTestCertificateEntity() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setSerial(TEST_CERTIFICATE_SERIAL);
        certificateEntity.setRevocationTime(null);
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setSubject(TEST_CERTIFICATE_SUBJECT);
        certificateEntity.setUserId(TEST_USER_ID);
        certificateEntity.setNotValidBefore(TEST_NOT_VALID_BEFORE);
        certificateEntity.setNotValidAfter(TEST_NOT_VALID_AFTER);
        certificateEntity.setX509PEMCertificate(TEST_CERTIFICATE.getBytes());

        final UseEntity useEntity = new UseEntity();
        useEntity.setUse(TEST_USE);
        useEntity.setConfig(null);

        certificateEntity.setUse(useEntity);

        return certificateEntity;
    }

    @Test(expected = CertificateNotFoundException.class)
    public void confirmNonExisting() {
        final String confirmationToken = "does not exist";
        confirmableCertificatePersistenceLayer.confirm(confirmationToken,
                TEST_USER_ID);
    }
}