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

package ch.zhaw.ba.anath.authentication;

import ch.zhaw.ba.anath.authentication.pki.CertificatePermissionEvaluator;
import ch.zhaw.ba.anath.authentication.users.UserPermissionEvaluator;
import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;

/**
 * @author Rafael Ostertag
 */
public class AnathPermissionEvaluatorTest {

    private UserPermissionEvaluator userPermissionEvaluator;
    private CertificatePermissionEvaluator certificatePermissionEvaluator;
    private AnathPermissionEvaluator anathPermissionEvaluator;

    @Before
    public void setUp() {
        this.certificatePermissionEvaluator = mock(CertificatePermissionEvaluator.class);
        this.userPermissionEvaluator = mock(UserPermissionEvaluator.class);

        this.anathPermissionEvaluator = new AnathPermissionEvaluator(userPermissionEvaluator,
                certificatePermissionEvaluator);
    }

    @Test
    public void hasPermission3CertificateListItemDto() {
        anathPermissionEvaluator.hasPermission(null, new CertificateListItemDto(), null);
        then(certificatePermissionEvaluator).should().hasPermission(any(), any(), any());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void hasPermission3AnyObject() {
        anathPermissionEvaluator.hasPermission(null, new Object(), null);
    }

    @Test
    public void hasPermission4UserTargetType() {
        anathPermissionEvaluator.hasPermission(null, null, UserPermissionEvaluator.TARGET_TYPE, null);
        then(userPermissionEvaluator).should().hasPermission(any(), any(), anyString(), any());
        then(certificatePermissionEvaluator).should(never()).hasPermission(any(), any(), anyString(), any());
    }

    @Test
    public void hasPermission4CertifiateTargetType() {
        anathPermissionEvaluator.hasPermission(null, null, CertificatePermissionEvaluator.TARGET_TYPE, null);
        then(certificatePermissionEvaluator).should().hasPermission(any(), any(), anyString(), any());
        then(userPermissionEvaluator).should(never()).hasPermission(any(), any(), anyString(), any());
    }

    @Test
    public void hasPermission4UnknownTargetType() {
        final boolean result = anathPermissionEvaluator.hasPermission(null, null, "should not exist", null);
        assertThat(result, is(false));
        then(certificatePermissionEvaluator).should(never()).hasPermission(any(), any(), anyString(), any());
        then(userPermissionEvaluator).should(never()).hasPermission(any(), any(), anyString(), any());
    }
}