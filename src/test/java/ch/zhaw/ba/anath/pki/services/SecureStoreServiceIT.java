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

import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("tests")
@TestPropertySource(properties = {
        "anath.secret-key=abcdefghijklmnopqrst1234"
})
@Transactional(transactionManager = "pkiTransactionManager")
public class SecureStoreServiceIT {
    private static final String TEST_KEY = "test.key";
    @PersistenceContext(unitName = "pki")
    EntityManager entityManager;

    @Autowired
    private SecureStoreService secureStoreService;

    @Test
    public void putNewKey() {
        final byte[] testData = new byte[]{'a', 'b', 'c'};
        secureStoreService.put(TEST_KEY, testData);

        final Optional<Byte[]> optionalData = secureStoreService.get(TEST_KEY);
        assertThat(optionalData.isPresent(), is(true));

        final Byte[] bytes = optionalData.get();
        final byte[] actual = ArrayUtils.toPrimitive(bytes);

        assertThat(actual, is(testData));
    }

    @Test
    public void putExistingKey() {
        secureStoreService.put(TEST_KEY, new byte[]{'a', 'b', 'c'});
        entityManager.flush();
        entityManager.clear();

        final byte[] testData = new byte[]{'d', 'e', 'f'};
        secureStoreService.put(TEST_KEY, testData);

        final Optional<Byte[]> optionalData = secureStoreService.get(TEST_KEY);
        assertThat(optionalData.isPresent(), is(true));

        final Byte[] bytes = optionalData.get();
        final byte[] actual = ArrayUtils.toPrimitive(bytes);

        assertThat(actual, is(testData));
    }

    @Test
    public void multipleBlockSize() {
        final byte[] testData = "Data exceeding block size".getBytes();
        secureStoreService.put(TEST_KEY, testData);

        final Optional<Byte[]> optionalData = secureStoreService.get(TEST_KEY);
        assertThat(optionalData.isPresent(), is(true));

        final Byte[] bytes = optionalData.get();
        final byte[] actual = ArrayUtils.toPrimitive(bytes);

        assertThat(actual, is(testData));
    }
}