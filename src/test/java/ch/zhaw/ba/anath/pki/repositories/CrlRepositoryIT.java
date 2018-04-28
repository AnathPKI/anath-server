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

package ch.zhaw.ba.anath.pki.repositories;

import ch.zhaw.ba.anath.pki.entities.CrlEntity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

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
public class CrlRepositoryIT {
    @Autowired
    private TestEntityManager testEntityManager;
    @Autowired
    private CrlRepository crlRepository;

    @Test
    public void findOne() {
        final CrlEntity crlEntity = makeDefaultEntity();
        testEntityManager.persistAndFlush(crlEntity);

        final Optional<CrlEntity> one = crlRepository.findOne(crlEntity.getId());
        assertThat(one.isPresent(), is(true));

        final Optional<CrlEntity> none = crlRepository.findOne(42L);
        assertThat(none.isPresent(), is(false));
    }

    private CrlEntity makeDefaultEntity() {
        final CrlEntity crlEntity = new CrlEntity();
        crlEntity.setThisUpdate(new Timestamp(1));
        crlEntity.setNextUpdate(new Timestamp(2));
        crlEntity.setX509PEMCrl(new byte[]{'a'});
        return crlEntity;
    }

    @Test
    public void findAllOrderByThisUpdateDesc() {
        final CrlEntity crlEntity1 = new CrlEntity();
        crlEntity1.setThisUpdate(new Timestamp(1));
        crlEntity1.setNextUpdate(new Timestamp(2));
        crlEntity1.setX509PEMCrl(new byte[]{'a'});
        testEntityManager.persistAndFlush(crlEntity1);

        final CrlEntity crlEntity2 = new CrlEntity();
        crlEntity2.setThisUpdate(new Timestamp(10));
        crlEntity2.setNextUpdate(new Timestamp(20));
        crlEntity2.setX509PEMCrl(new byte[]{'b'});
        testEntityManager.persistAndFlush(crlEntity2);

        final List<CrlEntity> allOrderByThisUpdateDesc = crlRepository.findAllOrderByThisUpdateDesc();
        assertThat(allOrderByThisUpdateDesc, hasSize(2));

        assertThat(allOrderByThisUpdateDesc.get(0).getX509PEMCrl(), is(equalTo(new byte[]{'b'})));
    }

    @Test
    public void save() {
        final CrlEntity crlEntity = makeDefaultEntity();
        crlRepository.save(crlEntity);

        final Optional<CrlEntity> one = crlRepository.findOne(crlEntity.getId());
        assertThat(one.isPresent(), is(true));
    }

    @Test
    public void deleteById() {
        final CrlEntity crlEntity = makeDefaultEntity();
        testEntityManager.persistAndFlush(crlEntity);

        final Optional<CrlEntity> one = crlRepository.findOne(crlEntity.getId());
        assertThat(one.isPresent(), is(true));

        crlRepository.deleteById(crlEntity.getId());

        final Optional<CrlEntity> none = crlRepository.findOne(crlEntity.getId());
        assertThat(none.isPresent(), is(false));
    }
}