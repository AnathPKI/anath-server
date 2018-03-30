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

package ch.zhaw.ba.anath.controllers.pki;

import ch.zhaw.ba.anath.AnathException;
import ch.zhaw.ba.anath.authentication.spring.AnathSecurityHelper;
import ch.zhaw.ba.anath.controllers.AnathMediaType;
import ch.zhaw.ba.anath.dto.pki.SigningRequestDto;
import ch.zhaw.ba.anath.pki.core.Certificate;
import ch.zhaw.ba.anath.pki.core.CertificateSigningRequest;
import ch.zhaw.ba.anath.pki.core.PEMCertificateSigningRequestReader;
import ch.zhaw.ba.anath.pki.services.SigningService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(value = "/sign",
        consumes = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE,
        produces = AnathMediaType.APPLICATION_VND_ANATH_V1_JSON_VALUE)
@Slf4j
public class SigningController {
    private static final String ERROR_READING_PEM_OBJECT_FROM_REQUEST = "Error reading PEM object from request";
    private final SigningService signingService;

    public SigningController(SigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('USER')")
    public HttpEntity<Void> signCertificateRequest(@RequestBody @Validated SigningRequestDto signingRequestDto) {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                signingRequestDto
                        .getCsr()
                        .getPem()
                        .getPem().getBytes());

        try (Reader reader = new InputStreamReader(byteArrayInputStream)) {
            final PEMCertificateSigningRequestReader pemCertificateSigningRequestReader = new
                    PEMCertificateSigningRequestReader(reader);

            final CertificateSigningRequest certificateSigningRequest = pemCertificateSigningRequestReader
                    .certificationRequest();

            final String username = AnathSecurityHelper.getUsername();
            final Certificate certificate = signingService.signCertificate(certificateSigningRequest, username,
                    signingRequestDto.getUse
                            ());

            final String serialAsString = certificate.getSerial().toString();
            final URI uri = linkTo(methodOn(CertificatesController.class).getCertificate(serialAsString)).toUri();

            return ResponseEntity
                    .created(uri)
                    .contentType(AnathMediaType.APPLICATION_VND_ANATH_V1_JSON)
                    .build();
        } catch (IOException e) {
            log.error(ERROR_READING_PEM_OBJECT_FROM_REQUEST);
            throw new AnathException(ERROR_READING_PEM_OBJECT_FROM_REQUEST);
        }
    }
}
