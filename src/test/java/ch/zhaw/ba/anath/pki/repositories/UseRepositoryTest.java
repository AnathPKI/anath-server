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

import ch.zhaw.ba.anath.pki.entities.UseEntity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import javax.transaction.Transactional;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@DataJpaTest
@TestPropertySource(properties = {
        "spring.datasource.platform=h2"
})
@Transactional
public class UseRepositoryTest {
    @Autowired
    private TestEntityManager testEntityManager;

    @Autowired
    private UseRepository useRepository;

    @Test
    public void findOne() {
        final UseEntity useEntity = new UseEntity();

        useEntity.setConfig(null);
        useEntity.setUse("openvpn");
        testEntityManager.persistAndFlush(useEntity);

        // Must be defined by default
        final Optional<UseEntity> plainOptional = useRepository.findOne(UseEntity.DEFAULT_USE);
        assertThat(plainOptional.isPresent(), is(true));
        assertThat(plainOptional.get().getConfig(), is(nullValue()));

        final Optional<UseEntity> openVpnOptional = useRepository.findOne("openvpn");
        assertThat(openVpnOptional.isPresent(), is(true));
        assertThat(openVpnOptional.get().getConfig(), is(nullValue()));

        final Optional<UseEntity> notFoundOptional = useRepository.findOne("does not exist");
        assertThat(notFoundOptional.isPresent(), is(false));
    }

    @Test
    public void findAll() {
        final UseEntity useEntity = new UseEntity();

        useEntity.setConfig(null);
        useEntity.setUse("openvpn");
        testEntityManager.persistAndFlush(useEntity);

        final List<UseEntity> all = useRepository.findAll();
        assertThat(all, hasSize(2));
    }

    @Test
    public void save() {
        final UseEntity useEntity = new UseEntity();

        useEntity.setConfig(null);
        useEntity.setUse("openvpn");

        useRepository.save(useEntity);
        testEntityManager.flush();
        testEntityManager.clear();

        final Optional<UseEntity> openvpn = useRepository.findOne("openvpn");
        assertThat(openvpn.isPresent(), is(true));
    }

    @Test
    public void saveDuplicate() {
        final UseEntity useEntity = new UseEntity();

        useEntity.setConfig(null);
        useEntity.setUse("openvpn");

        useRepository.save(useEntity);
        testEntityManager.flush();
        testEntityManager.clear();

        final UseEntity useEntity1 = new UseEntity();
        useEntity1.setConfig(null);
        useEntity1.setUse("openvpn");

        testEntityManager.flush();
        testEntityManager.clear();
    }
}