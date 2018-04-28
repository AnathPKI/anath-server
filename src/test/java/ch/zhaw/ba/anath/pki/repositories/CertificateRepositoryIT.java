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

package ch.zhaw.ba.anath.pki.repositories;

import ch.zhaw.ba.anath.TestHelper;
import ch.zhaw.ba.anath.pki.core.UuidCertificateSerialProvider;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.Is.is;

/**
 * We need our schema, hibernate does not provide a big enough id type.
 *
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@DataJpaTest
@ActiveProfiles("tests")
@TestPropertySource(properties = {
        "spring.datasource.platform=h2"
})
@Transactional
public class CertificateRepositoryIT {
    public static final String TEST_SUBJECT = "subject";
    public static final String TEST_USER_ID = "user_id";
    public static final long TEST_REVOKE_TIMESTAMP = 1000000L;
    private final UuidCertificateSerialProvider uuidCertificateSerialProvider = new UuidCertificateSerialProvider();
    @Autowired
    private TestEntityManager testEntityManager;
    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    public void findOne() {
        final CertificateEntity certificateEntity = makeCertificateEntity();

        testEntityManager.persistAndFlush(certificateEntity);

        Optional<CertificateEntity> entityOptional = certificateRepository.findOne(certificateEntity.getId());

        assertThat(entityOptional.isPresent(), is(true));

        entityOptional = certificateRepository.findOne(999999L);
        assertThat(entityOptional.isPresent(), is(false));
    }

    @Test
    public void findAll() {
        final CertificateEntity certificateEntity1 = makeCertificateEntity();
        final CertificateEntity certificateEntity2 = makeCertificateEntity();
        certificateEntity2.setSubject("another subject");

        testEntityManager.persistAndFlush(certificateEntity1);
        testEntityManager.persistAndFlush(certificateEntity2);

        final List<CertificateEntity> all = certificateRepository.findAll();
        assertThat(all, hasSize(2));
    }

    @Test
    public void findAllByUserId() {
        final CertificateEntity certificateEntity1 = makeCertificateEntity();
        final CertificateEntity certificateEntity2 = makeCertificateEntity();
        certificateEntity2.setSubject("another subject");

        final CertificateEntity certificateEntity3 = makeCertificateEntity();
        certificateEntity3.setSubject("another subject 2");
        certificateEntity3.setUserId("another user id");

        testEntityManager.persistAndFlush(certificateEntity1);
        testEntityManager.persistAndFlush(certificateEntity2);
        testEntityManager.persistAndFlush(certificateEntity3);

        final List<CertificateEntity> all = certificateRepository.findAllByUserId(TEST_USER_ID);
        assertThat(all, hasSize(2));

        final List<CertificateEntity> onlyOne = certificateRepository.findAllByUserId("another user id");
        assertThat(onlyOne, hasSize(1));

        final List<CertificateEntity> empty = certificateRepository.findAllByUserId("does not exist");
        assertThat(empty, hasSize(0));
    }

    @Test
    public void findAllByUserIdAndStatus() {
        final CertificateEntity certificateEntity1 = makeCertificateEntity();
        certificateEntity1.setStatus(CertificateStatus.REVOKED);
        final CertificateEntity certificateEntity2 = makeCertificateEntity();
        certificateEntity2.setSubject("another subject");

        testEntityManager.persistAndFlush(certificateEntity1);
        testEntityManager.persistAndFlush(certificateEntity2);

        final List<CertificateEntity> revoked = certificateRepository.findAllByUserIdAndStatus(TEST_USER_ID,
                CertificateStatus.REVOKED);

        assertThat(revoked, hasSize(1));
        assertThat(revoked.get(0), is(equalTo(certificateEntity1)));

        final List<CertificateEntity> valid = certificateRepository.findAllByUserIdAndStatus(TEST_USER_ID,
                CertificateStatus.VALID);

        assertThat(valid, hasSize(1));
        assertThat(valid.get(0), is(equalTo(certificateEntity2)));
    }

    @Test
    public void save() {
        final CertificateEntity certificateEntity = makeCertificateEntity();
        certificateRepository.save(certificateEntity);

        testEntityManager.flush();
        testEntityManager.clear();
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void saveDuplicateSerial() {
        final CertificateEntity certificateEntity = makeCertificateEntity();

        certificateRepository.save(certificateEntity);

        testEntityManager.flush();
        testEntityManager.clear();

        certificateEntity.setId(null);
        certificateEntity.setSubject("bla");

        certificateRepository.save(certificateEntity);

        testEntityManager.flush();
        testEntityManager.clear();
    }

    private CertificateEntity makeCertificateEntity() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setSerial(uuidCertificateSerialProvider.serial());
        certificateEntity.setNotValidBefore(nowTimestamp());
        certificateEntity.setNotValidAfter(nowTimestamp());
        certificateEntity.setSubject(TEST_SUBJECT);
        certificateEntity.setX509PEMCertificate(new byte[]{'a'});
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setUserId(TEST_USER_ID);

        final UseEntity useEntity = new UseEntity();
        useEntity.setUse(UseEntity.DEFAULT_USE);
        useEntity.setConfig(null);
        certificateEntity.setUse(useEntity);
        return certificateEntity;
    }

    private Timestamp nowTimestamp() {
        return new Timestamp(System.currentTimeMillis());
    }

    @Test
    public void findOneBySerial() {
        final CertificateEntity certificateEntity = makeCertificateEntity();
        testEntityManager.persistAndFlush(certificateEntity);
        testEntityManager.clear();

        final Optional<CertificateEntity> found = certificateRepository.findOneBySerial(certificateEntity
                .getSerial());
        assertThat(found.isPresent(), is(true));

        final Optional<CertificateEntity> notFound = certificateRepository.findOneBySerial(BigInteger.ZERO);
        assertThat(notFound.isPresent(), is(false));
    }

    @Test
    public void findAllBySubject() {
        final CertificateEntity certificateEntity = makeCertificateEntity();
        testEntityManager.persistAndFlush(certificateEntity);
        testEntityManager.clear();

        List<CertificateEntity> allBySubject = certificateRepository.findAllBySubject(certificateEntity
                .getSubject());
        assertThat(allBySubject, hasSize(1));

        allBySubject = certificateRepository.findAllBySubject("should not exist");
        assertThat(allBySubject, hasSize(0));
    }

    @Test
    public void findAllRevoked() {
        List<CertificateEntity> allRevokedEmpty = certificateRepository.findAllRevoked();
        assertThat(allRevokedEmpty, is(empty()));

        final CertificateEntity nonRevokedEntity = makeCertificateEntity();
        testEntityManager.persistAndFlush(nonRevokedEntity);

        allRevokedEmpty = certificateRepository.findAllRevoked();
        assertThat(allRevokedEmpty, is(empty()));

        final CertificateEntity revokedCertificateEntity1 = makeCertificateEntity();
        revokedCertificateEntity1.setNotValidAfter(TestHelper.timeInFuture());
        revokedCertificateEntity1.setSubject(TEST_SUBJECT + "another1");
        revokedCertificateEntity1.setSerial(BigInteger.ONE.add(BigInteger.ONE));
        revokedCertificateEntity1.setStatus(CertificateStatus.REVOKED);
        revokedCertificateEntity1.setRevocationTime(new Timestamp(TEST_REVOKE_TIMESTAMP));
        testEntityManager.persistAndFlush(revokedCertificateEntity1);

        List<CertificateEntity> allRevoked = certificateRepository.findAllRevoked();
        assertThat(allRevoked, hasSize(1));

        final CertificateEntity revokedCertificateEntity2 = makeCertificateEntity();
        revokedCertificateEntity2.setNotValidAfter(TestHelper.timeInFuture());
        revokedCertificateEntity2.setSubject(TEST_SUBJECT + "another2");
        revokedCertificateEntity2.setSerial(BigInteger.ONE.add(BigInteger.ONE).add(BigInteger.ONE));
        revokedCertificateEntity2.setStatus(CertificateStatus.REVOKED);
        revokedCertificateEntity2.setRevocationTime(new Timestamp(TEST_REVOKE_TIMESTAMP + TEST_REVOKE_TIMESTAMP));
        testEntityManager.persistAndFlush(revokedCertificateEntity2);

        allRevoked = certificateRepository.findAllRevoked();
        assertThat(allRevoked, hasSize(2));
        assertThat(allRevoked.get(0).getSubject(), is(TEST_SUBJECT + "another1"));
        assertThat(allRevoked.get(1).getSubject(), is(TEST_SUBJECT + "another2"));

        final CertificateEntity revokedCertificateEntity3 = makeCertificateEntity();
        revokedCertificateEntity3.setSubject(TEST_SUBJECT + "another3");
        revokedCertificateEntity3.setSerial(BigInteger.ONE.add(BigInteger.ONE).add(BigInteger.ONE).add(BigInteger.ONE));
        revokedCertificateEntity3.setStatus(CertificateStatus.REVOKED);
        // intentionally don't set the revocation time. The certificate has revoked status, thus the application must
        // handle such broken revocations.
        revokedCertificateEntity3.setRevocationTime(null);
        testEntityManager.persistAndFlush(revokedCertificateEntity3);

        allRevoked = certificateRepository.findAllRevoked();
        assertThat(allRevoked, hasSize(3));
        assertThat(allRevoked.get(0).getSubject(), is(TEST_SUBJECT + "another3"));
        assertThat(allRevoked.get(1).getSubject(), is(TEST_SUBJECT + "another1"));
        assertThat(allRevoked.get(2).getSubject(), is(TEST_SUBJECT + "another2"));
    }

    @Test
    public void findAllRevokedDoNotIncludeExpiredRevoked() {
        final CertificateEntity revokedCertificateEntity1 = makeCertificateEntity();
        revokedCertificateEntity1.setNotValidAfter(TestHelper.timeInPast());
        revokedCertificateEntity1.setSubject(TEST_SUBJECT + "another1");
        revokedCertificateEntity1.setSerial(BigInteger.ONE);
        revokedCertificateEntity1.setStatus(CertificateStatus.REVOKED);
        revokedCertificateEntity1.setRevocationTime(new Timestamp(TEST_REVOKE_TIMESTAMP));
        testEntityManager.persistAndFlush(revokedCertificateEntity1);

        List<CertificateEntity> allRevoked = certificateRepository.findAllRevoked();
        assertThat(allRevoked, is(empty()));
    }
}