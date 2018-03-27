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

package ch.zhaw.ba.anath.authentication;

import ch.zhaw.ba.anath.config.properties.AnathProperties;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.springframework.stereotype.Component;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

/**
 * Argon password encoder. Implementation taken from OWASP Password Storage Cheat Sheet.
 * <p>
 * See https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet (2018-03-27).
 *
 * @author Rafael Ostertag
 */
@Component
public class Argon2PasswordEncoder {
    private static final String ITERATIONS_KEY = "ITERATIONS";
    private static final String MEMORY_KEY = "MEMORY";
    private static final String PARALLELISM_KEY = "PARALLELISM";
    private final AnathProperties anathProperties;

    public Argon2PasswordEncoder(AnathProperties anathProperties) {
        this.anathProperties = anathProperties;
    }

    /**
     * Compute a hash of a password.
     * Password provided is wiped from the memory at the end of this method
     *
     * @param password Password to hash
     * @param charset  Charset of the password
     *
     * @return the hash in format "$argon2i$v=19$m=128000,t=3,
     * p=4$sfSe5MewORVlg8cDtxOTbg$uqWx4mZvLI092oJ8ZwAjAWU0rrBSDQkOezxAuvrE5dM"
     */
    public String hash(char[] password, Charset charset) {
        String hash;
        Argon2 argon2Hasher = null;
        try {
            // Create instance
            argon2Hasher = createInstance();
            //Create options
            Map<String, String> options = loadParameters();
            int iterationsCount = Integer.parseInt(options.get(ITERATIONS_KEY));
            int memoryAmountToUse = Integer.parseInt(options.get(MEMORY_KEY));
            int threadToUse = Integer.parseInt(options.get(PARALLELISM_KEY));
            //Compute and return the hash
            hash = argon2Hasher.hash(iterationsCount, memoryAmountToUse, threadToUse, password, charset);
        } finally {
            //Clean the password from the memory
            if (argon2Hasher != null) {
                argon2Hasher.wipeArray(password);
            }
        }
        return hash;
    }

    /**
     * Verifies a password against a hash
     * Password provided is wiped from the memory at the end of this method
     *
     * @param hash     Hash to verify
     * @param password Password to which hash must be verified against
     * @param charset  Charset of the password
     *
     * @return True if the password matches the hash, false otherwise.
     */
    public boolean verify(String hash, char[] password, Charset charset) {
        Argon2 argon2Hasher = null;
        boolean isMatching;
        try {
            // Create instance
            argon2Hasher = createInstance();
            //Apply the verification (hash computation options are included in the hash itself)
            isMatching = argon2Hasher.verify(hash, password, charset);
        } finally {
            //Clean the password from the memory
            if (argon2Hasher != null) {
                argon2Hasher.wipeArray(password);
            }
        }
        return isMatching;
    }

    /**
     * Create and configure an Argon2 instance
     *
     * @return The Argon2 instance
     */
    private Argon2 createInstance() {
        // Create and return the instance
        return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2i);
    }

    /**
     * Load Argon2 options to use for hashing.
     *
     * @return A map with the options
     */
    private Map<String, String> loadParameters() {
        final AnathProperties.Authentication.Argon2 argon2Properties = anathProperties.getAuthentication()
                .getArgon2();
        Map<String, String> options = new HashMap<>();
        options.put(ITERATIONS_KEY, Integer.toString(argon2Properties.getIterations()));
        options.put(MEMORY_KEY, Integer.toString(argon2Properties.getMemory()));
        options.put(PARALLELISM_KEY, Integer.toString(argon2Properties.getParallelism()));
        return options;
    }
}
