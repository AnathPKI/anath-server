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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.pki.dto.CertificateListItemDto;
import ch.zhaw.ba.anath.pki.dto.CertificateResponseDto;
import ch.zhaw.ba.anath.pki.dto.bits.CertificateValidityBit;
import ch.zhaw.ba.anath.pki.dto.bits.PemBit;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.CertificateStatus;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Rafael Ostertag
 */
@Slf4j
@Service
@Transactional(transactionManager = "pkiTransactionManager")
public class CertificateService {
    private final CertificateRepository certificateRepository;
    private final ConfigurationTemplateService configurationTemplateService;

    public CertificateService(CertificateRepository certificateRepository, ConfigurationTemplateService
            configurationTemplateService) {
        this.certificateRepository = certificateRepository;
        this.configurationTemplateService = configurationTemplateService;
    }

    /**
     * Get certificate by serial number.
     *
     * @param serial serial number.
     *
     * @return {@link CertificateResponseDto} instance.
     */
    public CertificateResponseDto getCertificate(BigInteger serial) {
        final CertificateEntity certificateEntity = getCertificateEntityOrThrow(serial);

        return certificateEntityToCertificateResponseDto
                (certificateEntity);
    }

    private CertificateEntity getCertificateEntityOrThrow(BigInteger serial) {
        final Optional<CertificateEntity> optionalCertificateEntity = certificateRepository.findOneBySerial(serial);
        return optionalCertificateEntity.orElseThrow(() -> {
            log.error("Certificate with serial {} not found", serial.toString());
            return new CertificateNotFoundException("Certificate not found");
        });
    }

    /**
     * Get PEM Encoded certificate.
     *
     * @param serial certificate serial number.
     *
     * @return string representation of PEM encoded certificate.
     */
    public String getPlainPEMEncodedCertificate(BigInteger serial) {
        final CertificateEntity certificateEntity = getCertificateEntityOrThrow(serial);
        return new String(certificateEntity.getX509PEMCertificate());
    }

    /**
     * Get all certificates.
     *
     * @return {@link List} of {@link CertificateListItemDto}s.
     */
    public List<CertificateListItemDto> getAll() {
        final List<CertificateEntity> all = certificateRepository.findAll();
        return all
                .stream()
                .map(this::certificateEntityToListItemDto)
                .collect(Collectors.toList());
    }

    private CertificateListItemDto certificateEntityToListItemDto(CertificateEntity certificateEntity) {
        final CertificateListItemDto certificateListItemDto = new CertificateListItemDto();
        certificateListItemDto.setSerial(certificateEntity.getSerial());
        certificateListItemDto.setSubject(certificateEntity.getSubject());
        certificateListItemDto.setUse(certificateEntity.getUse().getUse());
        certificateListItemDto.setValid(CertificateValidityUtils.isValid(certificateEntity));
        return certificateListItemDto;
    }

    private CertificateResponseDto certificateEntityToCertificateResponseDto(CertificateEntity certificateEntity) {
        final CertificateResponseDto certificateResponseDto = new CertificateResponseDto();
        certificateResponseDto.setUse(certificateEntity.getUse().getUse());
        final String configuration = processConfigurationTemplateAndEncodeBase64(certificateEntity);
        certificateResponseDto.setConfig(configuration);
        final PemBit certificatePemBit = createCertificatePemBit(certificateEntity);
        certificateResponseDto.setCert(certificatePemBit);

        final CertificateValidityBit certificateValidityBit = createCertificateValidityBit(certificateEntity);
        certificateResponseDto.setValidity(certificateValidityBit);
        return certificateResponseDto;
    }

    private String processConfigurationTemplateAndEncodeBase64(CertificateEntity certificateEntity) {
        final UseEntity use = certificateEntity.getUse();
        if (use.getConfig() == null || use.getConfig().length == 0) {
            return null;
        }

        final String pemEncodedUserCertificate = new String(certificateEntity.getX509PEMCertificate());
        final String configurationTemplate = new String(ArrayUtils.toPrimitive(use.getConfig()));

        log.info("Process configuration template for '{}'", certificateEntity.getSubject());
        final String configuration = configurationTemplateService.process(pemEncodedUserCertificate,
                configurationTemplate);

        log.info("Base64 encode configuration");
        return Base64.getEncoder().encodeToString(configuration.getBytes());
    }

    private CertificateValidityBit createCertificateValidityBit(CertificateEntity certificateEntity) {
        final CertificateValidityBit certificateValidityBit = new CertificateValidityBit();
        certificateValidityBit.setExpired(CertificateValidityUtils.isExpired(certificateEntity));
        certificateValidityBit.setNotAfter(certificateEntity.getNotValidAfter());
        certificateValidityBit.setNotBefore(certificateEntity.getNotValidBefore());
        certificateValidityBit.setRevoked(certificateEntity.getStatus() == CertificateStatus.REVOKED);
        certificateValidityBit.setRevokeReason(certificateEntity.getRevokeReason());
        return certificateValidityBit;
    }

    private PemBit createCertificatePemBit(CertificateEntity certificateEntity) {
        final PemBit pemBit = new PemBit();
        pemBit.setPem(new String(certificateEntity.getX509PEMCertificate()));
        return pemBit;
    }
}
