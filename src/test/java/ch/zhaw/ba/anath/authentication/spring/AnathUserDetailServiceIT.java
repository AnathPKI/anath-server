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

package ch.zhaw.ba.anath.authentication.spring;

import ch.zhaw.ba.anath.users.entities.UserEntity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Transactional(transactionManager = "userTransactionManager")
public class AnathUserDetailServiceIT {
    @PersistenceContext(unitName = "users")
    private EntityManager entityManager;

    @Autowired
    private AnathUserDetailService anathUserDetailService;

    @Test
    public void loadAdminByUsername() {
        final UserEntity adminUserEntity = new UserEntity();
        adminUserEntity.setPassword("password");
        adminUserEntity.setEmail("admin@example.com");
        adminUserEntity.setLastname("admin");
        adminUserEntity.setFirstname("admin");
        adminUserEntity.setAdmin(true);

        persistAndFlush(adminUserEntity);
        final UserDetails userDetails = anathUserDetailService.loadUserByUsername("admin@example.com");

        assertThat(userDetails.getUsername(), is(equalTo("admin@example.com")));
        assertThat(userDetails.getAuthorities(), hasSize(1));
        assertThat(userDetails.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN")), is(true));
    }

    private void persistAndFlush(UserEntity userEntity) {
        entityManager.persist(userEntity);
        entityManager.flush();
    }

    @Test
    public void loadUserByUsername() {
        final UserEntity adminUserEntity = new UserEntity();
        adminUserEntity.setPassword("password");
        adminUserEntity.setEmail("user@example.com");
        adminUserEntity.setLastname("user");
        adminUserEntity.setFirstname("user");
        adminUserEntity.setAdmin(false);

        persistAndFlush(adminUserEntity);
        final UserDetails userDetails = anathUserDetailService.loadUserByUsername("user@example.com");

        assertThat(userDetails.getUsername(), is(equalTo("user@example.com")));
        assertThat(userDetails.getAuthorities(), hasSize(1));
        assertThat(userDetails.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_USER")), is(true));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void loadUserByNonExistingUsername() {
        anathUserDetailService.loadUserByUsername("admin@example.com");
    }
}