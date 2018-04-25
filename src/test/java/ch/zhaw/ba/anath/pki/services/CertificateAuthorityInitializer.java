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

import ch.zhaw.ba.anath.pki.core.TestConstants;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author Rafael Ostertag
 */
public class CertificateAuthorityInitializer {
    @PersistenceContext(unitName = "pki")
    private EntityManager entityManager;
    @Autowired
    private SecureStoreService secureStoreService;

    protected void initializeCa() throws IOException {
        initializeCaCertificate();
        initializeCaPrivateKey();
    }

    protected void initializeCaPrivateKey() throws IOException {
        try (InputStream privateKeyInputStream = new FileInputStream(TestConstants.CA_KEY_FILE_NAME)) {
            final byte[] privateKey = IOUtils.toByteArray(privateKeyInputStream);
            secureStoreService.put(CertificateAuthorityService.SECURE_STORE_CA_PRIVATE_KEY, privateKey);
            flushAndClear();
        }
    }

    protected void initializeCaCertificate() throws IOException {
        try (InputStream certificateInputStream = new FileInputStream(TestConstants.CA_CERT_FILE_NAME)) {
            final byte[] certificate = IOUtils.toByteArray(certificateInputStream);
            secureStoreService.put(CertificateAuthorityService.SECURE_STORE_CA_CERTIFICATE, certificate);
            flushAndClear();
        }
    }

    protected void flushAndClear() {
        entityManager.flush();
        entityManager.clear();
    }
}
