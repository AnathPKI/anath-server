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

package ch.zhaw.ba.anath.users.repositories;

import ch.zhaw.ba.anath.users.entities.UserEntity;
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

import java.util.List;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
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
public class UserRepositoryIT {
    private static final String EMAIL = "email";
    private static final String PASSWORD = "password";
    private static final String FIRSTNAME = "firstname";
    private static final String LASTNAME = "lastname";
    @Autowired
    private TestEntityManager testEntityManager;
    @Autowired
    private UserRepository userRepository;

    @Test
    public void findOne() {
        final Optional<UserEntity> nonExisting = userRepository.findOne(1L);
        assertThat(nonExisting.isPresent(), is(false));

        final UserEntity testEntity = makeTestEntity();
        testEntityManager.persistAndFlush(testEntity);
        testEntityManager.clear();

        final Optional<UserEntity> existing = userRepository.findOne(testEntity.getId());
        assertThat(existing.isPresent(), is(true));

        final UserEntity actualEntity = existing.get();
        compareWithTestEntity(actualEntity, testEntity);
    }

    private void compareWithTestEntity(UserEntity actualEntity, UserEntity testEntity) {
        assertThat(actualEntity.getId(), is(testEntity.getId()));
        assertThat(actualEntity.getAdmin(), is(testEntity.getAdmin()));
        assertThat(actualEntity.getEmail(), is(testEntity.getEmail()));
        assertThat(actualEntity.getPassword(), is(testEntity.getPassword()));
        assertThat(actualEntity.getFirstname(), is(testEntity.getFirstname()));
        assertThat(actualEntity.getLastname(), is(testEntity.getLastname()));
    }

    private UserEntity makeTestEntity() {
        final UserEntity userEntity = new UserEntity();
        userEntity.setAdmin(true);
        userEntity.setEmail(EMAIL);
        userEntity.setPassword(PASSWORD);
        userEntity.setFirstname(FIRSTNAME);
        userEntity.setLastname(LASTNAME);
        return userEntity;
    }

    @Test
    public void findOneByEmail() {
        final Optional<UserEntity> nonExisting = userRepository.findOneByEmail("must not exist");
        assertThat(nonExisting.isPresent(), is(false));

        final UserEntity testEntity = makeTestEntity();
        testEntityManager.persistAndFlush(testEntity);
        testEntityManager.clear();

        final Optional<UserEntity> oneByEmail = userRepository.findOneByEmail(EMAIL);
        assertThat(oneByEmail.isPresent(), is(true));

        final UserEntity actualEntity = oneByEmail.get();
        compareWithTestEntity(actualEntity, testEntity);
    }

    @Test
    public void findAll() {
        List<UserEntity> all = userRepository.findAll();
        assertThat(all, hasSize(0));

        final UserEntity userEntity1 = makeTestEntity();
        testEntityManager.persistAndFlush(userEntity1);

        final UserEntity userEntity2 = makeTestEntity();
        userEntity2.setEmail("another " + EMAIL);
        testEntityManager.persistAndFlush(userEntity2);

        all = userRepository.findAll();
        assertThat(all, hasSize(2));
    }

    @Test
    public void save() {
        final UserEntity testEntity = makeTestEntity();
        userRepository.save(testEntity);

        testEntityManager.flush();
        testEntityManager.clear();

        final UserEntity actualEntity = testEntityManager.find(UserEntity.class, testEntity.getId());
        compareWithTestEntity(actualEntity, testEntity);
    }

    @Test
    public void delete() {
        final UserEntity testEntity = makeTestEntity();
        testEntityManager.persistAndFlush(testEntity);

        userRepository.deleteById(testEntity.getId());

        final UserEntity userEntity = testEntityManager.find(UserEntity.class, testEntity.getId());
        assertThat(userEntity, is(nullValue()));
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void saveDuplicateEmail() {
        final UserEntity testEntity1 = makeTestEntity();
        testEntityManager.persistAndFlush(testEntity1);

        // We do change all fields but email.
        final UserEntity testEntity2 = makeTestEntity();
        testEntity2.setLastname("another " + LASTNAME);
        testEntity2.setFirstname("another " + FIRSTNAME);
        testEntity2.setPassword("another " + PASSWORD);
        testEntity2.setAdmin(false);

        userRepository.save(testEntity2);
        testEntityManager.flush();
        testEntityManager.clear();
    }

    @Test
    public void findAllByAdmin() {
        final UserEntity userEntity = makeTestEntity();
        userEntity.setAdmin(false);

        testEntityManager.persistAndFlush(userEntity);

        List<UserEntity> allByAdmin = userRepository.findAllByAdmin(false);
        assertThat(allByAdmin, hasSize(1));

        allByAdmin = userRepository.findAllByAdmin(true);
        assertThat(allByAdmin, hasSize(0));

        final UserEntity adminEntity = makeTestEntity();
        adminEntity.setEmail("another email");
        adminEntity.setAdmin(true);

        testEntityManager.persistAndFlush(adminEntity);

        allByAdmin = userRepository.findAllByAdmin(true);
        assertThat(allByAdmin, hasSize(1));
    }
}