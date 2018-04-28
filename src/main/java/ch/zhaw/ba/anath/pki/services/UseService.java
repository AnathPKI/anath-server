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

package ch.zhaw.ba.anath.pki.services;

import ch.zhaw.ba.anath.pki.dto.UseDto;
import ch.zhaw.ba.anath.pki.dto.UseItemDto;
import ch.zhaw.ba.anath.pki.entities.UseEntity;
import ch.zhaw.ba.anath.pki.exceptions.UseCreationException;
import ch.zhaw.ba.anath.pki.exceptions.UseDeleteException;
import ch.zhaw.ba.anath.pki.exceptions.UseNotFoundException;
import ch.zhaw.ba.anath.pki.exceptions.UseUpdateException;
import ch.zhaw.ba.anath.pki.repositories.UseRepository;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Rafael Ostertag
 */
@Service
@Slf4j
@Transactional(transactionManager = "pkiTransactionManager")
public class UseService {

    private static final String CANNOT_DELETE_PLAIN_USE_MESSAGE = "Cannot delete 'plain' use";
    private static final String CANNOT_UPDATE_PLAIN_USE_MESSAGE = "Must not update 'plain' use";
    private static final String PLAIN_USE = "plain";
    private final UseRepository useRepository;

    public UseService(UseRepository useRepository) {
        this.useRepository = useRepository;
    }

    public UseItemDto create(UseDto useDto) {
        final Optional<UseEntity> existingUseEntity = useRepository.findOne(useDto.getUse());
        if (existingUseEntity.isPresent()) {
            log.error("Cannot create use '{}'. Already exists", useDto.getUse());
            throw new UseCreationException("Use already exists");
        }
        final UseEntity useEntity = useDtoToUseEntity(useDto);

        useRepository.save(useEntity);
        log.info("Create new use '{}'", useDto.getUse());

        return useEntityToUseItemDto(useEntity);
    }

    private UseItemDto useEntityToUseItemDto(UseEntity useEntity) {
        final UseItemDto useItemDto = new UseItemDto();
        useItemDto.setUse(useEntity.getUse());
        return useItemDto;
    }

    private UseEntity useDtoToUseEntity(UseDto useDto) {
        final UseEntity useEntity = new UseEntity();
        useEntity.setUse(useDto.getUse());
        if (useDto.getConfiguration() == null) {
            useEntity.setConfig(null);
        } else {
            useEntity.setConfig(ArrayUtils.toObject(useDto.getConfiguration().getBytes()));
        }
        return useEntity;
    }

    public List<UseItemDto> getAll() {
        final List<UseEntity> all = useRepository.findAll();
        return all
                .stream()
                .map(this::useEntityToUseItemDto)
                .collect(Collectors.toList());
    }

    public void delete(String key) {
        if (key.equals(PLAIN_USE)) {
            log.error(CANNOT_DELETE_PLAIN_USE_MESSAGE);
            throw new UseDeleteException(CANNOT_DELETE_PLAIN_USE_MESSAGE);
        }

        final Optional<UseEntity> optionalUseEntity = useRepository.findOne(key);
        if (!optionalUseEntity.isPresent()) {
            log.error("Cannot delete non-existing use '{}'", key);
            throw new UseNotFoundException("Cannot delete non-existing use");
        }

        useRepository.deleteByUse(key);
        log.error("Delete use '{}'", key);
    }

    public UseDto getUse(String key) {
        final UseEntity useEntity = getUseEntityOrThrow(key);

        log.info("Retrieve use '{}'", key);
        return useEntityToUseDto(useEntity);
    }

    private UseEntity getUseEntityOrThrow(String key) {
        final Optional<UseEntity> useEntityOptional = useRepository.findOne(key);
        return useEntityOptional.orElseThrow(() -> {
            log.error("Cannot find use '{}'", key);
            return new UseNotFoundException("Use not found");
        });
    }

    private UseDto useEntityToUseDto(UseEntity useEntity) {
        final UseDto useDto = new UseDto();
        useDto.setUse(useEntity.getUse());
        if (useEntity.getConfig() == null) {
            useDto.setConfiguration(null);
        } else {
            final byte[] configuration = ArrayUtils.toPrimitive(useEntity.getConfig());
            useDto.setConfiguration(new String(configuration));
        }
        return useDto;
    }

    public UseItemDto updateUse(String key, String newConfiguration) {
        if (key.equals(PLAIN_USE)) {
            log.error(CANNOT_UPDATE_PLAIN_USE_MESSAGE);
            throw new UseUpdateException(CANNOT_UPDATE_PLAIN_USE_MESSAGE);
        }

        final UseEntity useEntity = getUseEntityOrThrow(key);
        if (newConfiguration == null) {
            useEntity.setConfig(null);
        } else {
            useEntity.setConfig(ArrayUtils.toObject(newConfiguration.getBytes()));
        }
        useRepository.save(useEntity);

        log.info("Updated use '{}'", key);
        return useEntityToUseItemDto(useEntity);
    }
}
