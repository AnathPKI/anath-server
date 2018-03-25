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

package ch.zhaw.ba.anath.pki;

import org.junit.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * @author Rafael Ostertag
 */
public class OneYearValidityTest {

    // We use 1 second, so that tests also pass on busy systems.
    private static final long TIME_DELTA_MILLIS = 1_000L;
    private static final long ONE_YEAR_IN_MILLIS = 365L * 24L * 60L * 60L * 1_000L;

    @Test
    public void from() {
        final OneYearValidity oneYearValidity = new OneYearValidity();

        final Date now = new Date();
        assertThat(oneYearValidity.from().getTime(), is(
                both(greaterThan(now.getTime() - TIME_DELTA_MILLIS))
                        .and(lessThan(now.getTime() + TIME_DELTA_MILLIS))
        ));
    }

    @Test
    public void to() {
        final OneYearValidity oneYearValidity = new OneYearValidity();

        final Date now = new Date();
        assertThat(oneYearValidity.to().getTime(), is(
                both(greaterThan(now.getTime() + ONE_YEAR_IN_MILLIS - TIME_DELTA_MILLIS))
                        .and(lessThan(now.getTime() + ONE_YEAR_IN_MILLIS + TIME_DELTA_MILLIS))
        ));
    }
}