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

package ch.zhaw.ba.anath.pki.utilities;

import ch.zhaw.ba.anath.pki.exceptions.ConfirmationTokenException;
import ch.zhaw.ba.anath.pki.services.ConfirmableCertificatePersistenceLayer;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.UUID;

/**
 * Create tokens to be used by {@link ConfirmableCertificatePersistenceLayer}.
 *
 * @author Rafael Ostertag
 */
@Slf4j
public class TokenCreator {
    private static final String HASH_ALGORITHM = "SHA256";
    private static final String SECURITY_PROVIDOER = "BC";
    private static final int UUID_SIZE_IN_BITS = 128;
    private static final int BITS_PER_BYTE = 8;
    private static final int SIZE_IN_BYTES_OF_UUID = UUID_SIZE_IN_BITS / BITS_PER_BYTE;

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public String token() {
        final UUID uuid = UUID.randomUUID();
        final byte[] hashedUuid = hashUuid(uuid);
        return Hex.toHexString(hashedUuid);
    }

    private byte[] hashUuid(UUID uuid) {
        try {
            byte[] uuidAsByteArray = uuidToByteArray(uuid);
            final MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM, SECURITY_PROVIDOER);
            return messageDigest.digest(uuidAsByteArray);
        } catch (NoSuchAlgorithmException e) {
            log.error("Algorithm {} not found", HASH_ALGORITHM);
            throw new ConfirmationTokenException("No algorithm found", e);
        } catch (NoSuchProviderException e) {
            log.error("Provider {} not found", SECURITY_PROVIDOER);
            throw new ConfirmationTokenException("Security Provider not found", e);
        }
    }

    private byte[] uuidToByteArray(UUID uuid) {
        final ByteBuffer buffer = ByteBuffer.allocate(SIZE_IN_BYTES_OF_UUID);
        buffer
                .putLong(uuid.getLeastSignificantBits())
                .putLong(uuid.getMostSignificantBits());

        byte[] byteArray = new byte[SIZE_IN_BYTES_OF_UUID];
        buffer.rewind();
        buffer.get(byteArray);

        return byteArray;
    }
}
