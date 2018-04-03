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

import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

import java.util.Optional;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;

/**
 * @author Rafael Ostertag
 */
public class ConfigurationTemplateServiceTest {
    private static final String TEST_TEMPLATE = "The CA Cert: ${caCertificate}. The user cert: ${userCertificate}.";

    private SecureStoreService secureStoreServiceMock;
    private ConfigurationTemplateService configurationTemplateService;

    @Before
    public void setUp() {
        secureStoreServiceMock = mock(SecureStoreService.class);
        configurationTemplateService = new ConfigurationTemplateService(secureStoreServiceMock);
    }

    @Test(expected = CertificateAuthorityNotInitializedException.class)
    public void processWithNoCa() {
        given(secureStoreServiceMock.get(CertificateAuthorityService.SECURE_STORE_CA_CERTIFICATE)).willReturn
                (Optional.empty());

        configurationTemplateService.process("bla", TEST_TEMPLATE);
    }

    @Test
    public void process() {
        final Byte[] testCa = ArrayUtils.toObject("CA CERT".getBytes());
        given(secureStoreServiceMock.get(CertificateAuthorityService.SECURE_STORE_CA_CERTIFICATE)).willReturn
                (Optional.of(testCa));

        final String expandedTemplate = configurationTemplateService.process("USER CERT", TEST_TEMPLATE);

        final String expected = "The CA Cert: CA CERT. The user cert USER CERT";
        assertThat(expandedTemplate, is(expandedTemplate));
    }

    @Test
    public void processMany() {
        final Byte[] testCa = ArrayUtils.toObject("CA CERT".getBytes());
        given(secureStoreServiceMock.get(CertificateAuthorityService.SECURE_STORE_CA_CERTIFICATE)).willReturn
                (Optional.of(testCa));

        String expandedTemplate = configurationTemplateService.process("USER CERT", TEST_TEMPLATE);
        String expected = "The CA Cert: CA CERT. The user cert USER CERT";
        assertThat(expandedTemplate, is(expandedTemplate));

        expandedTemplate = configurationTemplateService.process("USER CERT 2", TEST_TEMPLATE);
        expected = "The CA Cert: CA CERT. The user cert USER CERT 2";
        assertThat(expandedTemplate, is(expandedTemplate));

        then(secureStoreServiceMock).should().get(anyString());
    }
}