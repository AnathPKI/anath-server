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
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
public class CertificateValidityUtilsTest {

    @Test
    public void isExpired() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setNotValidAfter(TestHelper.timeInFuture());
        certificateEntity.setNotValidBefore(TestHelper.timeInPast());
        certificateEntity.setStatus(CertificateStatus.VALID);

        assertThat(CertificateValidityUtils.isExpired(certificateEntity), is(false));

        certificateEntity.setNotValidBefore(TestHelper.timeInFuture());
        certificateEntity.setNotValidAfter(TestHelper.timeEvenFurtherInFuture());

        assertThat(CertificateValidityUtils.isExpired(certificateEntity), is(true));

        certificateEntity.setNotValidBefore(TestHelper.timeEvenMoreInPast());
        certificateEntity.setNotValidAfter(TestHelper.timeInPast());
        assertThat(CertificateValidityUtils.isExpired(certificateEntity), is(true));
    }

    @Test
    public void isValid() {
        final CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setNotValidAfter(TestHelper.timeInFuture());
        certificateEntity.setNotValidBefore(TestHelper.timeInPast());
        certificateEntity.setStatus(CertificateStatus.VALID);

        // non expired certificate
        assertThat(CertificateValidityUtils.isValid(certificateEntity), is(true));
        certificateEntity.setStatus(CertificateStatus.REVOKED);
        assertThat(CertificateValidityUtils.isValid(certificateEntity), is(false));

        // expired non-revoked certificate
        certificateEntity.setStatus(CertificateStatus.VALID);
        certificateEntity.setNotValidBefore(TestHelper.timeInFuture());
        certificateEntity.setNotValidAfter(TestHelper.timeEvenFurtherInFuture());

        assertThat(CertificateValidityUtils.isValid(certificateEntity), is(false));

        certificateEntity.setNotValidBefore(TestHelper.timeEvenMoreInPast());
        certificateEntity.setNotValidAfter(TestHelper.timeInPast());
        assertThat(CertificateValidityUtils.isValid(certificateEntity), is(false));

        // expired, revoked certificate
        certificateEntity.setStatus(CertificateStatus.REVOKED);
        certificateEntity.setNotValidBefore(TestHelper.timeInFuture());
        certificateEntity.setNotValidAfter(TestHelper.timeEvenFurtherInFuture());

        assertThat(CertificateValidityUtils.isValid(certificateEntity), is(false));

        certificateEntity.setNotValidBefore(TestHelper.timeEvenMoreInPast());
        certificateEntity.setNotValidAfter(TestHelper.timeInPast());
        assertThat(CertificateValidityUtils.isValid(certificateEntity), is(false));
    }
}