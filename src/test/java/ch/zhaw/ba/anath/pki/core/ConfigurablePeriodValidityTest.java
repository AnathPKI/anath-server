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

package ch.zhaw.ba.anath.pki.core;

import ch.zhaw.ba.anath.pki.core.interfaces.CertificateValidityProvider;
import org.junit.Test;

import java.util.Date;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
public class ConfigurablePeriodValidityTest {
    private static final int ONE_SECOND_IN_MILLIS = 1000;
    private static final long ONE_DAY_IN_MILLIS = 24 * 60 * 60 * 1000L;
    private final CertificateValidityProvider configurableValidity = new ConfigurablePeriodValidity(1);

    @Test
    public void from() {
        final Date now = new Date();
        assertThat(configurableValidity.from().getTime(), is(both(greaterThan(now.getTime() - ONE_SECOND_IN_MILLIS))
                .and(lessThan(now
                .getTime() + ONE_SECOND_IN_MILLIS))));
    }

    @Test
    public void to() {
        final long delta = configurableValidity.to().getTime() - configurableValidity.from().getTime();
        assertThat(delta, is(both(greaterThan(ONE_DAY_IN_MILLIS - ONE_SECOND_IN_MILLIS)).and(lessThan
                (ONE_DAY_IN_MILLIS + ONE_SECOND_IN_MILLIS))));
    }
}