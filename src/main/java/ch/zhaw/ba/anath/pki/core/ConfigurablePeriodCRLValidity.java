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

package ch.zhaw.ba.anath.pki.core;

import ch.zhaw.ba.anath.pki.core.interfaces.CertificateRevocationListValidityProvider;

import java.util.Date;

/**
 * Provide dates making a CRL valid for a configurable period in days. The period is measured by calling
 * {@link #thisUpdate()}. This may lead to the difference of {@link #thisUpdate()} and {@link #nextUpdate()} being
 * more than the specified period. However, if used properly, the difference is only a few seconds, which in the
 * context of Certificate Revocation Lists does not matter.
 *
 * @author Rafael Ostertag
 */
public class ConfigurablePeriodCRLValidity implements CertificateRevocationListValidityProvider {
    private final long periodInMillis;

    public ConfigurablePeriodCRLValidity(int days) {
        if (days < 1) {
            throw new IllegalArgumentException("Days must not be less than 1");
        }

        this.periodInMillis = daysToMillis(days);
    }

    private long daysToMillis(int days) {
        return days * 24 * 60 * 60 * 1000L;
    }

    @Override
    public Date thisUpdate() {
        return new Date();
    }

    @Override
    public Date nextUpdate() {
        return new Date(thisUpdate().getTime() + periodInMillis);
    }
}
