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

import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.dto.RevocationReasonDto;
import ch.zhaw.ba.anath.pki.services.CertificateService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.hateoas.Resources;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;

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
@Slf4j
public class CertificatesController {
    private final CertificateService certificateService;

    public CertificatesController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @GetMapping(
            path = "/{serial}",
            consumes = MediaType.ALL_VALUE,
            produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and hasPermission(#serial, 'certificate', 'get'))")
    @ApiOperation(value = "Retrieve a User Certificate by Serial Number", notes =
            "This endpoint returns a 'application/vnd.anath.v1+json' representation of the resource when the " +
                    "client sent 'application/vnd.anath.v1+json'. In that case admin users may retrieve any " +
                    "certificate. Regular users are limited to their own certificates. When the client does not send " +
                    "an " +
                    "'Accept' header, or the content of the 'Accept' header is not 'application/vnd.anath.v1+json', " +
                    "the PEM encoded user certificate is returned an NO authentication is required.",
            response =
                    CertificateResponseDto
                            .class)
    public CertificateResponseDto getCertificate(@PathVariable BigInteger serial) {
        final CertificateResponseDto certificate = certificateService.getCertificate(serial);
        certificate.add(linkTo(methodOn(RevocationController.class).revoke(serial, new RevocationReasonDto())).withRel
                ("revoke"));
        certificate.add(linkTo(methodOn(CertificatesController.class).getPlainPemCertificate(serial)).withRel("pem"));
        return certificate;
    }

    @GetMapping(path = "/{serial}",
            consumes = MediaType.ALL_VALUE,
            produces = {PkixMediaType.APPLICATION_PKIX_CERT_VALUE, MediaType.ALL_VALUE}
    )
    @ResponseStatus(HttpStatus.OK)
    public HttpEntity<String> getPlainPemCertificate(@PathVariable BigInteger serial) {
        final String filename = serial.toString() + PkixMediaType.X509_CERTIFICATE_FILE_EXTENSION;
        return ResponseEntity
                .ok()
                .header(HttpHeaders.CONTENT_TYPE, PkixMediaType.APPLICATION_PKIX_CERT_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, String.format("attachment; filename=\"%s\"", filename))
                .body(certificateService.getPlainPEMEncodedCertificate(serial));

    }

    @GetMapping(
            consumes = MediaType.ALL_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('ADMIN') or hasRole('USER')")
    @ApiOperation(value = "Get all User Certificates")
    public Resources<CertificateListItemDto> getAll(HttpServletRequest httpServletRequest) {
        List<CertificateListItemDto> all = certificateService.getAll();

        boolean isAdmin = httpServletRequest.isUserInRole("ADMIN");
        String username = httpServletRequest.getUserPrincipal().getName();

        all = all.stream()
                .filter(x -> isAdmin || (x.getUserId() != null && x.getUserId().equals(username)))
                .map(this::addLinksToCertificateListItemDto)
                .collect(Collectors.toList());

        return new Resources<>(all, linkTo(CertificatesController.class).withRel("sign"));
    }

    private CertificateListItemDto addLinksToCertificateListItemDto(CertificateListItemDto certificateListItemDto) {
        certificateListItemDto.add(linkTo(methodOn(CertificatesController.class).getCertificate
                (certificateListItemDto.getSerial())).withSelfRel());
        certificateListItemDto.add(linkTo(methodOn(CertificatesController.class).getPlainPemCertificate
                (certificateListItemDto.getSerial())).withRel("pem"));
        certificateListItemDto.add(linkTo(methodOn(RevocationController.class).revoke
                (certificateListItemDto.getSerial(), new RevocationReasonDto())).withRel("revoke"));
        return certificateListItemDto;
    }
}
