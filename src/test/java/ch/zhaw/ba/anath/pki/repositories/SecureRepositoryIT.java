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

package ch.zhaw.ba.anath.pki.repositories;

import ch.zhaw.ba.anath.pki.entities.SecureEntity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@DataJpaTest
@ActiveProfiles("tests")
@TestPropertySource(properties = {
        "spring.datasource.platform=h2"
})
@Transactional
public class SecureRepositoryIT {
    @Autowired
    private TestEntityManager testEntityManager;

    @Autowired
    private SecureRepository secureRepository;

    @Test
    public void createEntity() {
        final SecureEntity secureEntity = new SecureEntity();
        secureEntity.setAlgorithm("algo");
        secureEntity.setData(new byte[]{1, 2});
        secureEntity.setIV(new byte[]{2, 3});
        secureEntity.setKey("the key");

        secureRepository.save(secureEntity);
        flushAndClear();

        final Optional<SecureEntity> one = secureRepository.findOne(secureEntity.getId());
        assertThat(one.isPresent(), is(true));
    }

    private void flushAndClear() {
        testEntityManager.flush();
        testEntityManager.clear();
    }

    @Test
    public void findEntityByKey() {
        final SecureEntity secureEntity = new SecureEntity();
        secureEntity.setAlgorithm("algo");
        secureEntity.setData(new byte[]{1, 2});
        secureEntity.setIV(new byte[]{2, 3});
        secureEntity.setKey("the key");

        testEntityManager.persistAndFlush(secureEntity);

        final Optional<SecureEntity> optionalSecureEntity = secureRepository.findOneByKey("the key");
        assertThat(optionalSecureEntity.isPresent(), is(true));

        final Optional<SecureEntity> nonexistingSecureEntity = secureRepository.findOneByKey("does not exist");
        assertThat(nonexistingSecureEntity.isPresent(), is(false));
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void createDuplicateKey() {
        final SecureEntity secureEntity = new SecureEntity();
        secureEntity.setAlgorithm("algo");
        secureEntity.setData(new byte[]{1, 2});
        secureEntity.setIV(new byte[]{2, 3});
        secureEntity.setKey("the key");

        testEntityManager.persistAndFlush(secureEntity);
        testEntityManager.clear();

        secureEntity.setId(null);
        secureRepository.save(secureEntity);
        testEntityManager.flush();
    }

    @Test
    public void deleteByKey() {
        final SecureEntity secureEntity = new SecureEntity();
        secureEntity.setAlgorithm("algo");
        secureEntity.setData(new byte[]{1, 2});
        secureEntity.setIV(new byte[]{2, 3});
        secureEntity.setKey("the key");

        secureRepository.save(secureEntity);
        flushAndClear();

        secureRepository.deleteByKey("the key");
        flushAndClear();

        final Optional<SecureEntity> secureEntityOptional = secureRepository.findOneByKey("the key");
        assertThat(secureEntityOptional.isPresent(), is(false));
    }
}