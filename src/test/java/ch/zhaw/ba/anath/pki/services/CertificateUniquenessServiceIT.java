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

import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAlreadyExistsException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.math.BigInteger;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("tests")
@Transactional(transactionManager = "pkiTransactionManager")
public class CertificateUniquenessServiceIT {
    @Autowired
    private CertificateUniquenessService certificateUniquenessService;

    @PersistenceContext(unitName = "pki")
    private EntityManager entityManager;

    @Test(expected = CertificateAlreadyExistsException.class)
    public void nonUniqueCertificate() {
        final CertificateEntity certificateEntity = makeValidCertificate();

        entityManager.persist(certificateEntity);
        entityManager.flush();
        entityManager.clear();

        certificateUniquenessService.testCertificateUniquenessInCertificateRepositoryOrThrow("subject");
    }

    @Test
    public void uniqueCertificateDueToStatus() {
        final CertificateEntity certificateEntity = makeValidCertificate();
        certificateEntity.setStatus(CertificateStatus.REVOKED);

        entityManager.persist(certificateEntity);
        entityManager.flush();
        entityManager.clear();

        certificateUniquenessService.testCertificateUniquenessInCertificateRepositoryOrThrow("subject");
        // Not throwing an exception is the test
    }

    @Test
    public void uniqueCertificateDueToValidity() {
        final CertificateEntity certificateEntity = makeValidCertificate();
        certificateEntity.setNotValidBefore(TestHelper.timeEvenMoreInPast());
        certificateEntity.setNotValidAfter(TestHelper.timeInPast());

        entityManager.persist(certificateEntity);
        entityManager.flush();
        entityManager.clear();

        certificateUniquenessService.testCertificateUniquenessInCertificateRepositoryOrThrow("subject");
        // Not throwing an exception is the test
    }

    @Test
    public void uniqueCertificateDueToUniqueSubject() {
        final CertificateEntity certificateEntity = makeValidCertificate();
        certificateEntity.setSubject("another subject");

        entityManager.persist(certificateEntity);
        entityManager.flush();
        entityManager.clear();

        certificateUniquenessService.testCertificateUniquenessInCertificateRepositoryOrThrow("subject");
        // Not throwing an exception is the test
    }

    public CertificateEntity makeValidCertificate() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setNotValidBefore(TestHelper.timeEvenMoreInPast());
        certificateEntity.setNotValidAfter(TestHelper.timeEvenFurtherInFuture());
        certificateEntity.setSubject("subject");
        certificateEntity.setX509PEMCertificate("cert".getBytes());
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setUserId("userid");
        certificateEntity.setSerial(BigInteger.TEN);

        final UseEntity useEntity = new UseEntity();
        useEntity.setUse("plain");
        certificateEntity.setUse(useEntity);
        return certificateEntity;
    }
}