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

package ch.zhaw.ba.anath.pki.repositories;

import ch.zhaw.ba.anath.pki.core.UuidCertificateSerialProvider;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
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
@Transactional
public class CertificateRepositoryTest {
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

        final List<CertificateEntity> all = certificateRepository.findAllByUserId("user_id");
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

        final List<CertificateEntity> revoked = certificateRepository.findAllByUserIdAndStatus("user_id",
                CertificateStatus.REVOKED);

        assertThat(revoked, hasSize(1));
        assertThat(revoked.get(0), is(equalTo(certificateEntity1)));

        final List<CertificateEntity> valid = certificateRepository.findAllByUserIdAndStatus("user_id",
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
        certificateEntity.setSubject("subject");
        certificateEntity.setX509PEMCertificate(new byte[]{'a'});
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setUserId("user_id");
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
}