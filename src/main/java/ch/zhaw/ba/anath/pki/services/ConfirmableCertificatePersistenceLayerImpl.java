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

import ch.zhaw.ba.anath.config.properties.AnathProperties;
import ch.zhaw.ba.anath.pki.core.exceptions.PKIException;
import ch.zhaw.ba.anath.pki.entities.CertificateEntity;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.CertificateNotFoundException;
import ch.zhaw.ba.anath.pki.repositories.CertificateRepository;
import ch.zhaw.ba.anath.pki.repositories.UseRepository;
import ch.zhaw.ba.anath.pki.utilities.TokenCreator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * @author Rafael Ostertag
 */
@Profile("confirm")
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class ConfirmableCertificatePersistenceLayerImpl implements ConfirmableCertificatePersistenceLayer {
    private final AnathProperties.Confirmation confirmationConfiguration;
    private final RedisTemplate<ConfirmationKey, CertificateEntity> redisTemplate;
    private final CertificateRepository certificateRepository;
    private final UseRepository useRepository;
    private final TokenCreator tokenCreator;

    public ConfirmableCertificatePersistenceLayerImpl(AnathProperties anathProperties, RedisTemplate<ConfirmationKey,
            CertificateEntity> redisTemplate, CertificateRepository certificateRepository, UseRepository
                                                              useRepository, TokenCreator tokenCreator) {
        this.confirmationConfiguration = anathProperties.getConfirmation();
        this.redisTemplate = redisTemplate;
        this.certificateRepository = certificateRepository;
        this.useRepository = useRepository;
        this.tokenCreator = tokenCreator;
        log.info("Confirmable Certificate Persistence Layer initialized");
    }

    @Override
    public String store(CertificateEntity certificateEntity) {
        final ValueOperations<ConfirmationKey, CertificateEntity> redisOperation =
                redisTemplate.opsForValue();

        final String token = tokenCreator.token();
        final ConfirmationKey confirmationKey = new ConfirmationKey(token, certificateEntity.getUserId());
        redisOperation.set(confirmationKey, certificateEntity, confirmationConfiguration.getTokenValidity(), TimeUnit
                .MINUTES);

        log.info("Signed Certificate stored to Redis pending confirmation");
        return token;
    }

    @Override
    public CertificateEntity confirm(String token, String userId) {
        final ValueOperations<ConfirmationKey, CertificateEntity> redisOperation =
                redisTemplate.opsForValue();

        final ConfirmationKey confirmationKey = new ConfirmationKey(token, userId);
        final CertificateEntity certificateEntity = redisOperation.get(confirmationKey);
        certificateFoundOrThrow(confirmationKey, certificateEntity);
        redisTemplate.delete(confirmationKey);

        // Suppose the use has been deleted in the meanwhile, we would not be able to save the entity.
        final CertificateEntity certificateEntityWithExistingUse = guaranteeUseExistence(certificateEntity);

        certificateRepository.save(certificateEntityWithExistingUse);

        log.info("Signed certificate retrieved from Redis and persisted");
        return certificateEntity;
    }

    private void certificateFoundOrThrow(ConfirmationKey confirmationKey, CertificateEntity certificateEntity) {
        if (certificateEntity == null) {
            log.error("No pending confirmation '{}'", confirmationKey);
            throw new CertificateNotFoundException("No pending confirmation");
        }

        log.info("Pending confirmation '{}' found for Certificate '{}'", confirmationKey, certificateEntity
                .getSubject());
    }

    /**
     * Takes a {@link CertificateEntity} and makes sure the {@link ch.zhaw.ba.anath.pki.entities.UseEntity} exists.
     * If it does not exist, the plain use is used. This method modifies the passed {@link CertificateEntity} as side
     * effect.
     *
     * @param certificateEntity {@link CertificateEntity} instance.
     *
     * @return {@link CertificateEntity} with a {@link UseEntity} guaranteed to exist.
     */
    private CertificateEntity guaranteeUseExistence(CertificateEntity certificateEntity) {
        final UseEntity initialUseOnCertificateEntity = certificateEntity.getUse();

        final Optional<UseEntity> optionalUse = useRepository.findOne(initialUseOnCertificateEntity.getUse());

        final UseEntity useEntityGuaranteedToExist = optionalUse.orElseGet(this::getPlainUseEntity);

        certificateEntity.setUse(useEntityGuaranteedToExist);

        return certificateEntity;
    }

    private UseEntity getPlainUseEntity() {
        log.warn("Provided use in CertificateEntity retrieved from Redis does not exist anymore. Resorting to default" +
                " 'plain' use.");
        // Per definition, this use must exist.
        final Optional<UseEntity> plain = useRepository.findOne("plain");

        return plain.orElseThrow(() -> {
            log.error("The 'plain' use cannot be found");
            return new PKIException("Cannot find default 'plain' use");
        });
    }
}
