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

import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.dto.RevocationReasonDto;
import ch.zhaw.ba.anath.pki.services.CertificateService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.hateoas.Resources;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.List;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(value = "/certificates",
        consumes = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE,
        produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE)
@Api(tags = {"Certificate Authority"})
public class CertificatesController {
    private final CertificateService certificateService;

    public CertificatesController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @GetMapping("/{serial}")
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and hasPermission(#serial, 'certificate', 'get'))")
    @ApiOperation(value = "Retrieve a User Certificate by Serial Number", notes = "Admin users may retrieve any " +
            "certificate. Regular users are limited to their own certificates.")
    public CertificateResponseDto getCertificate(@PathVariable BigInteger serial) {
        final CertificateResponseDto certificate = certificateService.getCertificate(serial);
        certificate.add(linkTo(methodOn(RevocationController.class).revoke(serial, new RevocationReasonDto())).withRel
                ("revoke"));
        certificate.add(linkTo(methodOn(CertificatesController.class).getPlainPemCertificate(serial)).withRel("pem"));
        return certificate;
    }

    @GetMapping(path = "/{serial}/pem",
            consumes = MediaType.ALL_VALUE,
            produces = {"application/pkix-certificate"})
    @ResponseStatus(HttpStatus.OK)
    @ApiOperation(value = "Retrieve a PEM Encoded User Certificate by Serial Number", authorizations = {})
    public HttpEntity<String> getPlainPemCertificate(@PathVariable BigInteger serial) {
        return new ResponseEntity<>(certificateService.getPlainPEMEncodedCertificate(serial), HttpStatus.OK);
    }

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    @ApiOperation(value = "Get all User Certificates")
    public Resources<CertificateListItemDto> getAll() {
        final List<CertificateListItemDto> all = certificateService.getAll();
        for (CertificateListItemDto certificateListItemDto : all) {
            certificateListItemDto.add(linkTo(methodOn(CertificatesController.class).getCertificate
                    (certificateListItemDto.getSerial())).withSelfRel());
            certificateListItemDto.add(linkTo(methodOn(CertificatesController.class).getPlainPemCertificate
                    (certificateListItemDto.getSerial())).withRel("pem"));
            certificateListItemDto.add(linkTo(methodOn(RevocationController.class).revoke
                    (certificateListItemDto.getSerial(), new RevocationReasonDto())).withRel("revoke"));
        }
        return new Resources<>(all, linkTo(SigningController.class).withRel("sign"));
    }
}
