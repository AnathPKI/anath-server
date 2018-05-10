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

package ch.zhaw.ba.anath.pki.controllers;

import ch.zhaw.ba.anath.pki.services.CertificateAuthorityService;
import ch.zhaw.ba.anath.pki.services.RevocationService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(value = "/")
@Slf4j
@Api(tags = {"Certificate Authority"})
public class CertificateAuthorityController {

    private final CertificateAuthorityService certificateAuthorityService;

    private final RevocationService revocationService;

    public CertificateAuthorityController(CertificateAuthorityService certificateAuthorityService,
                                          RevocationService revocationService) {
        this.certificateAuthorityService = certificateAuthorityService;
        this.revocationService = revocationService;
    }

    @GetMapping(
            path = "/ca.pem",
            consumes = MediaType.ALL_VALUE,
            produces = {PkixMediaType.APPLICATION_PKIX_CERT_VALUE, MediaType.ALL_VALUE}
    )
    @ResponseStatus(HttpStatus.OK)
    @ApiOperation(value = "Get the PEM Encoded X.509 CA Certificate", authorizations = {})
    public HttpEntity<String> getCaCertificate() {
        final String caCertificateString = certificateAuthorityService.getCertificate();
        final String filename = "ca" + PkixMediaType.X509_CERTIFICATE_FILE_EXTENSION;
        return ResponseEntity
                .ok()
                .header(HttpHeaders.CONTENT_TYPE, PkixMediaType.APPLICATION_PKIX_CERT_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, String.format("attachment; filename=\"%s\"", filename))
                .body(caCertificateString);
    }

    @GetMapping(
            path = "/crl.pem",
            consumes = MediaType.ALL_VALUE,
            produces = PkixMediaType.APPLICATION_PKIX_CRL_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @ApiOperation(value = "Get the PEM Encoded X.509 Certificate Revocation List",
            authorizations = {}
    )
    public HttpEntity<String> getCrl() {
        final String filename = "crl" + PkixMediaType.X509_CERTIFICATE_REVOCATION_LIST_FILE_EXTENSION;
        return ResponseEntity
                .ok()
                .header(HttpHeaders.CONTENT_TYPE, PkixMediaType.APPLICATION_PKIX_CRL_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, String.format("attachment; filename=\"%s\"", filename))
                .body(revocationService.getCrlPemEncoded());
    }

}
