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
import ch.zhaw.ba.anath.pki.exceptions.UseCreationException;
import ch.zhaw.ba.anath.pki.exceptions.UseDeleteException;
import ch.zhaw.ba.anath.pki.exceptions.UseNotFoundException;
import ch.zhaw.ba.anath.pki.exceptions.UseUpdateException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * @author Rafael Ostertag
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("tests")
@Transactional(transactionManager = "pkiTransactionManager")
public class UseServiceIT {

    private static final String TEST_USE = "test.use";
    @Autowired
    private UseService useService;

    @Test
    public void create() {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_USE);

        final UseItemDto useItemDto = useService.create(useDto);
        assertThat(useItemDto.getUse(), is(TEST_USE));

        final UseDto actual = useService.getUse(TEST_USE);
        assertThat(actual, is(equalTo(useDto)));
    }

    @Test(expected = UseCreationException.class)
    public void createExistingUse() {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_USE);

        useService.create(useDto);
        useService.create(useDto);
    }

    @Test
    public void getAll() {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_USE);

        useService.create(useDto);

        final List<UseItemDto> all = useService.getAll();
        assertThat(all, hasSize(2));
        assertThat(all.get(1).getUse(), is(TEST_USE));
    }

    @Test
    public void getAllEmpty() {
        final List<UseItemDto> all = useService.getAll();
        assertThat(all, hasSize(1));
    }

    @Test(expected = UseNotFoundException.class)
    public void deleteNonExisting() {
        useService.delete("does not exist");
    }

    @Test(expected = UseDeleteException.class)
    public void deletePlainMustNotSucceed() {
        useService.delete("plain");
    }

    @Test
    public void delete() {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_USE);

        useService.create(useDto);
        useService.delete(TEST_USE);

        try {
            useService.getUse(TEST_USE);
        } catch (UseNotFoundException e) {
            // that's ok, we've just deleted it
        }
    }

    @Test
    public void updateUse() {
        final UseDto useDto = new UseDto();
        useDto.setUse(TEST_USE);

        useService.create(useDto);

        final UseItemDto updatedItem = useService.updateUse(TEST_USE, "the configuration");
        assertThat(updatedItem.getUse(), is(TEST_USE));

        final UseDto use = useService.getUse(TEST_USE);
        assertThat(use.getUse(), is(TEST_USE));
        assertThat(use.getConfiguration(), is("the configuration"));
    }

    @Test(expected = UseNotFoundException.class)
    public void updateNonExistingUse() {
        useService.updateUse(TEST_USE, "the configuration");
    }

    @Test(expected = UseUpdateException.class)
    public void updatePlainUse() {
        useService.updateUse("plain", "the configuration");
    }
}