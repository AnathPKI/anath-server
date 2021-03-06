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

import ch.zhaw.ba.anath.pki.core.CertificateAuthority;
import ch.zhaw.ba.anath.pki.core.TestConstants;
import ch.zhaw.ba.anath.pki.dto.ImportCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("tests")
@TestPropertySource(properties = {
        "anath.secret-key=abcdefghijklmnopqrst1234"
})
@Transactional(transactionManager = "pkiTransactionManager")
public class CertificateAuthorityServiceIT {
    private static final String EXPECTED_IMPORT_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
            "MIID/jCCAuagAwIBAgIJAPQj6jMYDszkMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYD\n" +
            "VQQGEwJDSDEQMA4GA1UECAwHVGh1cmdhdTEQMA4GA1UEBwwHS2VmaWtvbjEYMBYG\n" +
            "A1UECgwPUmFmYWVsIE9zdGVydGFnMQwwCgYDVQQLDANkZXYxGDAWBgNVBAMMD1Jh\n" +
            "ZmFlbCBPc3RlcnRhZzEeMBwGCSqGSIb3DQEJARYPcmFmaUBndWVuZ2VsLmNoMB4X\n" +
            "DTE4MDIyNDE4NDQ1N1oXDTE5MDIyNDE4NDQ1N1owgZMxCzAJBgNVBAYTAkNIMRAw\n" +
            "DgYDVQQIDAdUaHVyZ2F1MRAwDgYDVQQHDAdLZWZpa29uMRgwFgYDVQQKDA9SYWZh\n" +
            "ZWwgT3N0ZXJ0YWcxDDAKBgNVBAsMA2RldjEYMBYGA1UEAwwPUmFmYWVsIE9zdGVy\n" +
            "dGFnMR4wHAYJKoZIhvcNAQkBFg9yYWZpQGd1ZW5nZWwuY2gwggEiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBDwAwggEKAoIBAQDe9/4o6/YCQ7h3uuepDzJOGu7YmSFjJJ8hE6BH\n" +
            "SckqaNLaqHkSvKmTzPt+CG2ZDaHeH6WhCfUWf8VL8gwt4QCEAjsM8Zs82+BT1HRg\n" +
            "tkaCaBeugLVWreG34clHcBnJgzoCRHFS92WXm16EmLU3ZVCy5ySgrDF0yNfPPWkr\n" +
            "hDFEtqIZ11t2pLNcdUsVnmP+68FEEo0B5zriUcbXUzE9NZLOzyaTWyWr/iipmBxv\n" +
            "D9BSQVx1NP3q3SBkDvNQIagjTxJtSg3ZYm2uzxUkOfSNsIC4yk35ySUL7470WCkF\n" +
            "MQQW4ZCE+KmvlmE+FfD7XIAVOYb7k2uPmO44AclQGjdxMNfZAgMBAAGjUzBRMB0G\n" +
            "A1UdDgQWBBQnZHOL8Uz4l8XpNZ0x/n2QJpTYyzAfBgNVHSMEGDAWgBQnZHOL8Uz4\n" +
            "l8XpNZ0x/n2QJpTYyzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCrNT5IwcDNWkdkvnGZzDIPqNvd5Sr/WQeRRCUJ8tM1wYRP+/beilekmaWl3mAl\n" +
            "0x5zGwUxBSgGv45q6j9FJu9rbwgk2x8/rVWycUCdGQJDzciGKUycE9bA4W8nV9dE\n" +
            "89nXXIo6aB2CC6+jiILTEHIiLoSIUeJTECe1tGh+fW4K7zdbVvmgxwEmP5oGwy13\n" +
            "uKpMYjUOaKZGgIjlN5+q+YCZIcwnC+iNma3/re3iNPyyRz5eX5/8h07R7EhL4bvr\n" +
            "ZDg7YsEg4AwLsuuIEz1W3ff+OQu6O4/Qe1PTc+/TDJgKd8wq5Nc1oOIMI6J8Ij21\n" +
            "3Pdg9DnfsOnW5/jb/3/ix9zA\n" +
            "-----END CERTIFICATE-----\n";

    @Autowired
    private CertificateAuthorityService certificateAuthorityService;

    @Autowired
    private CertificateAuthorityInitializationService certificateAuthorityInitializationService;

    @Autowired
    private SecureStoreService secureStoreService;

    private void importTestCertificateAuthority() throws IOException {
        final ImportCertificateAuthorityDto importCertificateAuthorityDto = new ImportCertificateAuthorityDto();
        importCertificateAuthorityDto.setPassword("");
        try (FileInputStream pkcs12File = new FileInputStream(TestConstants
                .PKCS12_ENCRYPTED_EMPTY_PASSWORD_FILE_NAME)) {
            importCertificateAuthorityDto.setPkcs12(Base64.getMimeEncoder().encodeToString(IOUtils.toByteArray
                    (pkcs12File)));
        }

        certificateAuthorityInitializationService.importPkcs12CertificateAuthority(importCertificateAuthorityDto);
    }

    @Test(expected = CertificateAuthorityNotInitializedException.class)
    public void getCertificateNonExistingCa() {
        certificateAuthorityService.getCertificate();
    }

    @Test(expected = CertificateAuthorityNotInitializedException.class)
    public void getCertificateAuthorityNonExistingCa() {
        certificateAuthorityService.getCertificateAuthority();
    }

    @Test
    public void getCertificate() throws IOException {
        importTestCertificateAuthority();

        final String pemEncodedCertificate = certificateAuthorityService.getCertificate();
        assertThat(pemEncodedCertificate, is(EXPECTED_IMPORT_CERTIFICATE));
    }

    @Test
    public void getCertificateAuthority() throws IOException {
        importTestCertificateAuthority();

        final CertificateAuthority certificateAuthority = certificateAuthorityService.getCertificateAuthority();
        assertThat(certificateAuthority.getCertificate(), is(not(nullValue())));
        assertThat(certificateAuthority.getPrivateKey(), is(not(nullValue())));
    }

}