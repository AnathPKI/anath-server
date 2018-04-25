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

import ch.zhaw.ba.anath.authentication.AnathSecurityHelper;
import ch.zhaw.ba.anath.config.properties.AnathProperties;
import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.core.CertificateSigningRequest;
import ch.zhaw.ba.anath.pki.dto.ConfirmationDto;
import ch.zhaw.ba.anath.pki.dto.SigningRequestDto;
import ch.zhaw.ba.anath.pki.services.SigningService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.Date;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

/**
 * Signing Controller which requires Confirmation. It exposes {@code POST /certificates} and {@code PUT
 * /certificates/confirm/{token}}.
 *
 * @author Rafael Ostertag
 */
@RestController("SigningWithConfirmation")
@Profile("confirm")
@RequestMapping(value = "/certificates",
        consumes = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE,
        produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE)
@Api(tags = {"Certificate Authority"})
@Slf4j
public class SigningControllerWithConfirmation {
    private static final long MILLIS_PER_MINUTE = 60 * 1000L;
    private final SigningService signingService;
    private final AnathProperties.Confirmation confirmationProperties;

    public SigningControllerWithConfirmation(SigningService signingService, AnathProperties anathProperties) {
        this.signingService = signingService;
        confirmationProperties = anathProperties.getConfirmation();

        log.info("Confirming Signing Controller loaded");
    }

    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    @PreAuthorize("hasRole('USER')")
    @ApiOperation(value = "Sign a PKCS#10 Certificate Signing Request with confirmation", notes = "Only users may " +
            "call this endpoint.")
    public ConfirmationDto signCertificateRequestWithConfirmation(
            @RequestBody @Validated SigningRequestDto signingRequestDto,
            HttpServletRequest httpServletRequest) {
        final InputStream byteArrayInputStream = new ByteArrayInputStream(
                signingRequestDto
                        .getCsr()
                        .getPem().getBytes());

        CertificateSigningRequest certificateSigningRequest = SigningControllerWithoutConfirmation
                .readCertificateSigningRequest(byteArrayInputStream);

        final String username = AnathSecurityHelper.getUsername();
        String token = signingService.tentativelySignCertificate(certificateSigningRequest, username,
                signingRequestDto.getUse());
        log.info("Expect confirmation for certificate signing request for user {}. Token:  {}", username, token);

        return confirmationDto();
    }

    @PutMapping("/confirm/{token:[a-zA-Z0-9]+}")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('USER')")
    @ApiOperation(value = "Confirm a PKCS#10 Certificate Signing Request", notes = "Only users may call this endpoint.")
    public HttpEntity<Void> confirmSigningRequest(@PathVariable String token, HttpServletRequest httpServletRequest) {
        final Certificate certificate = signingService.confirmTentativelySignedCertificate(token,
                httpServletRequest.getUserPrincipal().getName());

        final URI uri = linkTo(methodOn(CertificatesController.class).getCertificate(certificate.getSerial()))
                .toUri();

        return ResponseEntity
                .created(uri)
                .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                .build();
    }

    private ConfirmationDto confirmationDto() {
        final ConfirmationDto confirmationDto = new ConfirmationDto();
        confirmationDto.setNoLaterThan(noLatherThan());
        return confirmationDto;
    }

    private Date noLatherThan() {
        long minutesInMillis = minutesToMillis(confirmationProperties.getTokenValidity());
        return new Date(System.currentTimeMillis() + minutesInMillis);
    }

    private long minutesToMillis(int tokenValidityInMinutes) {
        return tokenValidityInMinutes * MILLIS_PER_MINUTE;
    }
}
