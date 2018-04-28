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

import ch.zhaw.ba.anath.pki.exceptions.CertificateAuthorityNotInitializedException;
import ch.zhaw.ba.anath.pki.exceptions.TemplateProcessingError;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Optional;

/**
 * Service processing configuration templates.
 * <p>
 * It replaces only {@code ${userCertificate}} and {@code ${caCertificate}} and expects the value of those variables
 * to be a PEM encoded certificate.
 * <p>
 * The CA certificate is read upon first use and kept in memory.
 * <p>
 * It provides {@code ${caCertificate}} be default from the secure store.
 *
 * @author Rafael Ostertag
 */
@Slf4j
@Service
@Transactional(transactionManager = "pkiTransactionManager")
public class ConfigurationTemplateService {
    private final SecureStoreService secureStoreService;
    private final VelocityEngine velocity;
    private String pemEncodedCaCertificate = null;

    public ConfigurationTemplateService(SecureStoreService secureStoreService) {
        this.secureStoreService = secureStoreService;
        velocity = new VelocityEngine();
        velocity.init();
    }

    /**
     * Expand the variables in template.
     *
     * @param userCertificate PEM encoded user certificate
     * @param template        the template
     *
     * @return expanded configuration
     */
    public String process(String userCertificate, String template) {
        readCACertificate();

        final VelocityContext velocityContext = createContext(userCertificate);

        try (
                ByteArrayOutputStream expandedTemplate = new ByteArrayOutputStream();
                OutputStreamWriter writer = new OutputStreamWriter(expandedTemplate)) {

            final boolean success = velocity.evaluate(velocityContext, writer, "configuration", template);
            if (success) {
                log.info("Template successfully processed");
            } else {
                log.error("Error processing velocity template");
            }

            writer.flush();

            return new String(expandedTemplate.toByteArray());
        } catch (TemplateProcessingError e) {
            log.error("Error processing template: {}", e.getMessage());
            throw new TemplateProcessingError("Error processing template", e);
        } catch (IOException e) {
            log.error("IO error while writing configuration to output buffer: {}", e.getCause());
            throw new TemplateProcessingError("IO error while processing template");
        }
    }

    private VelocityContext createContext(String userCertificate) {
        final VelocityContext velocityContext = new VelocityContext();
        velocityContext.put("caCertificate", pemEncodedCaCertificate);
        velocityContext.put("userCertificate", userCertificate);
        return velocityContext;
    }

    private void readCACertificate() {
        if (pemEncodedCaCertificate != null) {
            return;
        }

        final Optional<Byte[]> caCertificateOptional = secureStoreService.get(CertificateAuthorityService
                .SECURE_STORE_CA_CERTIFICATE);
        final Byte[] caCertificateBytes = caCertificateOptional.orElseThrow(() -> {
            log.error("No CA Certificate in secure store");
            return new CertificateAuthorityNotInitializedException("Not initialized");
        });

        pemEncodedCaCertificate = new String(ArrayUtils.toPrimitive(caCertificateBytes));
        log.info("Read and cached CA Certificate");
    }
}
