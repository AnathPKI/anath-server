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

package ch.zhaw.ba.anath.config.spring;

import ch.zhaw.ba.anath.config.properties.AnathProperties;
import ch.zhaw.ba.anath.pki.core.*;
import ch.zhaw.ba.anath.pki.core.extensions.CertificateExtensionsActionsFactoryInterface;
import ch.zhaw.ba.anath.pki.core.extensions.Rfc5280CAExtensionsActionsFactory;
import ch.zhaw.ba.anath.pki.core.interfaces.*;
import ch.zhaw.ba.anath.pki.corecustomizations.OrganizationAndEmailCertificateConstraint;
import ch.zhaw.ba.anath.users.services.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * @author Rafael Ostertag
 */
@Configuration
@Slf4j
public class PKICore {
    private final AnathProperties anathProperties;

    public PKICore(AnathProperties anathProperties) {
        this.anathProperties = anathProperties;
    }

    @Bean
    public CertificateSerialProvider certificateSerialProvider() {
        return new UuidCertificateSerialProvider();
    }

    @Bean
    public SecureRandomProvider secureRandomProvider() {
        return new SecureRandomProviderImpl();
    }

    @Bean
    public SignatureNameProvider signatureNameProvider() {
        return new Sha512WithRsa();
    }

    @Bean
    public CertificateValidityProvider certificateValidityProvider() {
        int days = anathProperties.getCertificateValidity();
        log.info("Use ConfigurablePeriodValidity with a value of {} day(s)", days);
        return new ConfigurablePeriodValidity(days);
    }

    @Bean
    public CertificateRevocationListValidityProvider certificateRevocationListValidityProvider() {
        int days = anathProperties.getCrlValidity();
        log.info("Use ConfigurablePeriodCRLValidity with a value of {} days(s)", days);
        return new ConfigurablePeriodCRLValidity(days);
    }

    @Bean
    public CertificateExtensionsActionsFactoryInterface certificateExtensionsActionsFactory() {
        return new Rfc5280CAExtensionsActionsFactory();
    }

    @Bean
    @Profile("tests")
    public CertificateConstraintProvider testCertificateConstraintProvider() {
        log.warn("Tests enabled, use OrganizationCertificateConstraint");
        return new OrganizationCertificateConstraint();
    }

    @Bean
    @Profile("!tests")
    public CertificateConstraintProvider certificateConstraintProvider(UserService userService) {
        log.info("Use production OrganizationAndEmailCertificateConstraint()");
        return new OrganizationAndEmailCertificateConstraint(userService);
    }
}
