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

import ch.zhaw.ba.anath.AnathExtensionMediaType;
import ch.zhaw.ba.anath.pki.dto.CreateSelfSignedCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.dto.ImportCertificateAuthorityDto;
import ch.zhaw.ba.anath.pki.services.CertificateAuthorityInitializationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.SmartValidator;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static org.springframework.hateoas.mvc.ControllerLinkBuilder.linkTo;
import static org.springframework.hateoas.mvc.ControllerLinkBuilder.methodOn;

/**
 * @author Rafael Ostertag
 */
@RestController
@RequestMapping(value = "/")
@Slf4j
@Api(tags = {"Certificate Authority"})
public class CertificateAuthorityInitializationController {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final CertificateAuthorityInitializationService certificateAuthorityInitializationService;
    private final SmartValidator validator;

    public CertificateAuthorityInitializationController(CertificateAuthorityInitializationService
                                                                certificateAuthorityInitializationService,
                                                        SmartValidator
                                                                validator) {
        this.certificateAuthorityInitializationService = certificateAuthorityInitializationService;
        this.validator = validator;
    }

    @PutMapping(
            path = "/",
            consumes = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE,
            produces = AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON_VALUE
    )
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    @ApiOperation(value = "Create a Self-Signed CA or import a CA Private Key and Certificate From a Base64 Encoded " +
            "PKCS#12 File")
    public HttpEntity<Void> initializeCa(@RequestBody byte[] data) throws NoSuchMethodException,
            MethodArgumentNotValidException {
        final Optional<ImportCertificateAuthorityDto> optionalImportDto = deserializeToImportCertificateAuthorityDto
                (data, new MethodParameter(CertificateAuthorityInitializationController.class
                        .getMethod("initializeCa", byte[].class), 0));

        final Optional<CreateSelfSignedCertificateAuthorityDto> optionalCreateSelfSignedCa =
                deserializeToCreateSelfSignedCertificateAuthorityDto(data, new MethodParameter
                        (CertificateAuthorityInitializationController.class
                                .getMethod("initializeCa", byte[].class), 0));

        if (!optionalImportDto.isPresent() && !optionalCreateSelfSignedCa.isPresent()) {
            throw new IllegalArgumentException("Unable to determine initialization type");
        }

        if (optionalImportDto.isPresent()) {
            final ImportCertificateAuthorityDto importCertificateAuthorityDto = optionalImportDto.get();
            certificateAuthorityInitializationService.importPkcs12CertificateAuthority(importCertificateAuthorityDto);
        }

        if (optionalCreateSelfSignedCa.isPresent()) {
            final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto =
                    optionalCreateSelfSignedCa.get();
            certificateAuthorityInitializationService.createSelfSignedCertificateAuthority
                    (createSelfSignedCertificateAuthorityDto);
        }
        final URI uri = linkTo(methodOn(CertificateAuthorityController.class).getCaCertificate()).toUri();

        return ResponseEntity
                .created(uri)
                .contentType(AnathExtensionMediaType.APPLICATION_VND_ANATH_EXTENSION_V1_JSON)
                .build();
    }

    private Optional<ImportCertificateAuthorityDto> deserializeToImportCertificateAuthorityDto(byte[] data,
                                                                                               MethodParameter
                                                                                                       methodParameter) throws MethodArgumentNotValidException {
        try {
            final ImportCertificateAuthorityDto importCertificateAuthorityDto = OBJECT_MAPPER.readValue(data,
                    ImportCertificateAuthorityDto.class);

            validateBeanOrThrow(importCertificateAuthorityDto, methodParameter);

            return Optional.of(importCertificateAuthorityDto);
        } catch (IOException e) {
            log.warn("Data read is not import data");
            return Optional.empty();
        }
    }

    private Optional<CreateSelfSignedCertificateAuthorityDto> deserializeToCreateSelfSignedCertificateAuthorityDto(
            byte[] data,
            MethodParameter methodParameter) throws MethodArgumentNotValidException {
        try {
            final CreateSelfSignedCertificateAuthorityDto createSelfSignedCertificateAuthorityDto = OBJECT_MAPPER
                    .readValue(data,
                            CreateSelfSignedCertificateAuthorityDto.class);

            validateBeanOrThrow(createSelfSignedCertificateAuthorityDto, methodParameter);

            return Optional.of(createSelfSignedCertificateAuthorityDto);
        } catch (IOException e) {
            log.warn("Data read is for creating a self signed ca");
            return Optional.empty();
        }
    }

    private void validateBeanOrThrow(Object object, MethodParameter methodParameter) throws
            MethodArgumentNotValidException {
        BeanPropertyBindingResult bindingResult =
                new BeanPropertyBindingResult(object, object.getClass().getName());
        validator.validate(object, bindingResult);
        if (bindingResult.hasErrors()) {
            throw new MethodArgumentNotValidException(methodParameter, bindingResult);
        }
    }
}
