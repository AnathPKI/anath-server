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

import java.sql.Timestamp;

/**
 * Utilities to determine the certificateValidity of a certificate represented by a {@link CertificateEntity}
 *
 * @author Rafael Ostertag
 */
public final class CertificateValidityUtils {
    private CertificateValidityUtils() {
        // intentionally empty
    }

    /**
     * Determines whether or not the certificate represented by {@link CertificateEntity} has been expired.
     * <p>
     * The current time is taken as reference to determine the expiration.
     *
     * @param certificateEntity {@link CertificateEntity} instance.
     *
     * @return {@code true} if the certificate is past its not-valid-after or before its not-valid-after, {@code
     * false} otherwise.
     */
    public static boolean isExpired(CertificateEntity certificateEntity) {
        final Timestamp timestampNow = getNowAsTimestamp();
        return certificateEntity.getNotValidBefore().compareTo(timestampNow) >= 0 ||
                certificateEntity.getNotValidAfter().compareTo(timestampNow) < 0;
    }

    public static boolean isValid(CertificateEntity certificateEntity) {
        return !isExpired(certificateEntity) && certificateEntity.getStatus() == CertificateStatus.VALID;
    }

    private static Timestamp getNowAsTimestamp() {
        return new Timestamp(System.currentTimeMillis());
    }
}
