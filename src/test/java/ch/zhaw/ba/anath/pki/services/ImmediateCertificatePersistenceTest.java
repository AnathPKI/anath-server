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
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;

/**
 * @author Rafael Ostertag
 */
public class ImmediateCertificatePersistenceTest {
    private static final String TEST_USER_ID = "test id";
    private CertificateRepository certificateRepositoryMock;
    private ConfirmableCertificatePersistenceLayer immediateCertificatePersistence;

    @Before
    public void setUp() {
        this.certificateRepositoryMock = mock(CertificateRepository.class);
        this.immediateCertificatePersistence = new ImmediateCertificatePersistence(certificateRepositoryMock);
    }

    @Test
    public void store() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setSerial(BigInteger.TEN);
        final String storeToken = immediateCertificatePersistence.store(certificateEntity);
        then(certificateRepositoryMock).should().save(certificateEntity);

        assertThat(storeToken, is(BigInteger.TEN.toString()));
    }

    @Test
    public void confirmExistingCertificate() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setSerial(BigInteger.TEN);
        given(certificateRepositoryMock.findOneBySerial(BigInteger.TEN)).willReturn(
                Optional.of(certificateEntity)
        );

        final CertificateEntity confirmedEntity = immediateCertificatePersistence.confirm(BigInteger.TEN.toString(),
                TEST_USER_ID);

        assertThat(confirmedEntity, is(certificateEntity));
    }

    @Test(expected = CertificateNotFoundException.class)
    public void confirmNonExistingCertificate() {
        given(certificateRepositoryMock.findOneBySerial(any())).willReturn(Optional.empty());

        immediateCertificatePersistence.confirm(BigInteger.TEN.toString(), TEST_USER_ID);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testCoercingOfNumberFormatException() {
        immediateCertificatePersistence.confirm("don't care about non numers", TEST_USER_ID);
    }
}