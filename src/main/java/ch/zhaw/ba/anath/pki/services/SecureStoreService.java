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
import ch.zhaw.ba.anath.pki.entities.SecureEntity;
import ch.zhaw.ba.anath.pki.exceptions.SecureStoreException;
import ch.zhaw.ba.anath.pki.repositories.SecureRepository;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.*;
import java.util.Optional;

/**
 * Service providing abstraction to the {@link SecureRepository}. It takes care of encrypting and decrypting data
 * upon store or retrieval. The password provided is hashed using SHA256, to provide the maximum key size for AES.
 *
 * @author Rafael Ostertag
 */
@Slf4j
@Service
@Transactional(transactionManager = "pkiTransactionManager")
public class SecureStoreService {
    private static final String CIPHER = "AES/CBC/PKCS5Padding";
    private static final String SECURITY_PROVIDER = "BC";
    private static final String DIGEST_ALGORITHM = "SHA256";

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    private final SecureRepository secureRepository;
    private final AnathProperties anathProperties;

    public SecureStoreService(SecureRepository secureRepository, AnathProperties anathProperties) {
        this.secureRepository = secureRepository;
        this.anathProperties = anathProperties;
    }

    /**
     * Store data encrypted in the {@link SecureRepository}. It assumes the data provided to be uncrypted.
     *
     * @param key  the key to store the data under. If the key exists, its value will be replaced.
     * @param data unencrypted data to be stored.
     */
    public void put(String key, byte[] data) {
        final Optional<SecureEntity> secureEntityOptional = secureRepository.findOneByKey(key);
        final SecureEntity secureEntity = secureEntityOptional.orElseGet(() -> {
            final SecureEntity newSecureEntity = new SecureEntity();
            newSecureEntity.setKey(key);
            return newSecureEntity;
        });

        final EncryptedData encryptedData = encryptData(data);
        secureEntity.setData(encryptedData.data);
        secureEntity.setIV(encryptedData.getIv());
        secureEntity.setAlgorithm(CIPHER);

        secureRepository.save(secureEntity);
    }

    /**
     * Encrypt the data. It creates a new IV.
     *
     * @param data data to be encrypted.
     *
     * @return a {@link EncryptedData} instance. The {@link EncryptedData#data} field contains the encrypted data.
     * The {@link EncryptedData#iv} field contains the IV.
     */
    private EncryptedData encryptData(byte[] data) {
        final Cipher cipher = instantiateCipher();
        final SecretKeySpec secretKeySpec = initializeSecretKeySpec(CIPHER);
        final IvParameterSpec ivParameterSpec = initializeRandomIV(cipher.getBlockSize());

        initializeCipherForEncryption(cipher, secretKeySpec, ivParameterSpec);
        final byte[] encryptedData = encryptWithCipher(cipher, data);

        return new EncryptedData(encryptedData, cipher.getIV());
    }

    private byte[] encryptWithCipher(Cipher cipher, byte[] data) {
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            return wrapIllegalBlockSizeException(e);
        } catch (BadPaddingException e) {
            return wrapBadPaddingException(e);
        }
    }

    private byte[] wrapBadPaddingException(BadPaddingException e) {
        log.error("Bad padding while encrypting/decrypting data for secure store: {}", e.getMessage());
        throw new SecureStoreException("Bad padding", e);
    }

    private byte[] wrapIllegalBlockSizeException(IllegalBlockSizeException e) {
        log.error("Illegal block size while encrypting data for secure store: {}", e.getMessage());
        throw new SecureStoreException("Illegal block size", e);
    }

    private void initializeCipherForEncryption(Cipher cipher, SecretKeySpec secretKeySpec, IvParameterSpec
            ivParameterSpec) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        } catch (InvalidKeyException e) {
            wrapInvalidKeyException(cipher, e);
        } catch (InvalidAlgorithmParameterException e) {
            wrapInvalidAlgorithmParameterException(cipher, e);
        }
    }

    private void initializeCipherForDecryption(Cipher cipher, SecretKeySpec secretKeySpec, IvParameterSpec
            ivParameterSpec) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        } catch (InvalidKeyException e) {
            wrapInvalidKeyException(cipher, e);
        } catch (InvalidAlgorithmParameterException e) {
            wrapInvalidAlgorithmParameterException(cipher, e);
        }
    }

    private void wrapInvalidAlgorithmParameterException(Cipher cipher, InvalidAlgorithmParameterException e) {
        log.error("Invalid algorithm parameters for cipher '{}': {}", cipher, e.getMessage());
        throw new SecureStoreException("Invalid algorithm parameters", e);
    }

    private void wrapInvalidKeyException(Cipher cipher, InvalidKeyException e) {
        log.error("Invalid key for cipher '{}': {}", cipher, e.getMessage());
        throw new SecureStoreException("Invalid key", e);
    }

    private SecretKeySpec initializeSecretKeySpec(String cipher) {
        byte[] hashedPassword = hashPassword();
        return new SecretKeySpec(hashedPassword, cipher);
    }

    private byte[] hashPassword() {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGORITHM);
            messageDigest.update(anathProperties.getSecretKey().getBytes(Charset.defaultCharset()));
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            wrapNoSuchAlgorithmExceptionAndThrow(DIGEST_ALGORITHM, e);
            // Won't be reached
            return new byte[0];
        }
    }

    private IvParameterSpec initializeRandomIV(int blockSize) {
        try {
            final SecureRandom strongRNG = SecureRandom.getInstanceStrong();
            final byte[] randomIv = new byte[blockSize];
            strongRNG.nextBytes(randomIv);

            return new IvParameterSpec(randomIv);
        } catch (NoSuchAlgorithmException e) {
            log.error("Unable to initialize strong RNG: {}", e.getMessage());
            throw new SecureStoreException("Unable to initialize strong RNG", e);
        }
    }

    private IvParameterSpec initializeIV(byte[] iv) {
        return new IvParameterSpec(iv);
    }

    /**
     * Instantiate default cipher using {@value #CIPHER} and provider {@value #SECURITY_PROVIDER},
     *
     * @return {@link Cipher} instance.
     */
    private Cipher instantiateCipher() {
        return instantiateCipher(CIPHER, SECURITY_PROVIDER);
    }

    /**
     * Instantiate cipher.
     *
     * @param cipherSpec cipher specfification
     * @param provider   provider
     *
     * @return {@link Cipher} instance.
     */
    private Cipher instantiateCipher(String cipherSpec, String provider) {
        try {
            return Cipher.getInstance(cipherSpec, provider);
        } catch (NoSuchAlgorithmException e) {
            return wrapNoSuchAlgorithmExceptionAndThrow(cipherSpec, e);
        } catch (NoSuchProviderException e) {
            return wrapNoSuchProviderExceptionAndThrow(provider,e);
        } catch (NoSuchPaddingException e) {
            log.error("Unsupported padding in cipher '%s': ", cipherSpec, e.getMessage());
            throw new SecureStoreException("Unsupported padding", e);
        }
    }

    private Cipher wrapNoSuchProviderExceptionAndThrow(String provider, NoSuchProviderException e) {
        log.error("Security provider '{}' not found: {}", provider, e.getMessage());
        throw new SecureStoreException(String.format("Security provider not found '%s'", provider), e);
    }

    private Cipher wrapNoSuchAlgorithmExceptionAndThrow(String cipher, NoSuchAlgorithmException e) {
        log.error("Cannot initialize cipher '{}': {}", cipher, e.getMessage());
        throw new SecureStoreException(String.format("Unable to initialize cipher '%s'", cipher), e);
    }

    /**
     * Retrieve data from {@link SecureRepository}. The data will be decrypted before returned.
     *
     * @param key the key to lookup the data.
     *
     * @return non-empty {@link Optional} if the key has been found, otherwise empty {@link Optional}.
     */
    public Optional<Byte[]> get(String key) {
        final Optional<SecureEntity> secureEntityOptional = secureRepository.findOneByKey(key);
        if (!secureEntityOptional.isPresent()) {
            return Optional.empty();
        }

        final SecureEntity secureEntity = secureEntityOptional.get();

        final Cipher cipher = instantiateCipher(secureEntity.getAlgorithm(), SECURITY_PROVIDER);
        final SecretKeySpec secretKeySpec = initializeSecretKeySpec(secureEntity.getAlgorithm());
        final IvParameterSpec ivParameterSpec = initializeIV(secureEntity.getIV());
        initializeCipherForDecryption(cipher, secretKeySpec, ivParameterSpec);

        return Optional.of(ArrayUtils.toObject(decryptData(cipher, secureEntity.getData())));
    }

    private byte[] decryptData(Cipher cipher, byte[] data) {
        try {
            return cipher.doFinal(data);
        } catch (BadPaddingException e) {
            return wrapBadPaddingException(e);
        } catch (IllegalBlockSizeException e) {
            return wrapIllegalBlockSizeException(e);
        }
    }

    @Value
    private class EncryptedData {
        private byte[] data;
        private byte[] iv;
    }
}

