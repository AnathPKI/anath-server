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

package ch.zhaw.ba.anath.pki.controllers;

import ch.zhaw.ba.anath.pki.dto.CreateSelfSignedCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.dto.ImportCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.services.CertificateAuthorityInitializationService;
import ch.zhaw.ba.anath.pki.services.CertificateAuthorityService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(value = "/ca",
        consumes = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE,
        produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE)
@Api(tags = {"Certificate Authority"})
public class CertificateAuthorityController {
    private final CertificateAuthorityService certificateAuthorityService;
    private final CertificateAuthorityInitializationService certificateAuthorityInitializationService;

    public CertificateAuthorityController(CertificateAuthorityService certificateAuthorityService,
                                          CertificateAuthorityInitializationService
                                                  certificateAuthorityInitializationService) {
        this.certificateAuthorityService = certificateAuthorityService;
        this.certificateAuthorityInitializationService = certificateAuthorityInitializationService;
    }

    @GetMapping(
            consumes = MediaType.ALL_VALUE,
            produces = "application/pkix-cert"
    )
    @ResponseStatus(HttpStatus.OK)
    @ApiOperation(value = "Get the PEM Encoded X.509 CA Certificate", authorizations = {})
    public HttpEntity<String> getCaCertificate() {
        String caCertificateString = certificateAuthorityService.getCertificate();
        return ResponseEntity.ok(caCertificateString);
    }

    @PutMapping(
            path = "/import"
    )
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    @ApiOperation(value = "Import a CA Private Key and Certificate From a Base64 Encoded PKCS#12 File")
    public HttpEntity<Void> importCa(@RequestBody @Validated ImportCertificateAuthorityDto
                                             importCertificateAuthorityDto) {
        certificateAuthorityInitializationService.importPkcs12CertificateAuthority(importCertificateAuthorityDto);
        final URI uri = linkTo(methodOn(CertificateAuthorityController.class).getCaCertificate()).toUri();

        return ResponseEntity
                .created(uri)
                .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                .build();
    }

    @PutMapping(path = "/create")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    @ApiOperation(value = "Create a Self-Signed CA")
    public HttpEntity<Void> createSelfSigned(@RequestBody @Validated CreateSelfSignedCertificateAuthorityDto
                                                     createSelfSignedCertificateAuthorityDto) {
        certificateAuthorityInitializationService.createSelfSignedCertificateAuthority
                (createSelfSignedCertificateAuthorityDto);
        final URI uri = linkTo(methodOn(CertificateAuthorityController.class).getCaCertificate()).toUri();

        return ResponseEntity
                .created(uri)
                .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                .build();
    }
}
