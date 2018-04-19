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

package ch.zhaw.ba.anath.pki.core.tools;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.stream.Collectors;

/**
 * @author Rafael Ostertag
 */
public class ListSecurityProviders {
    public static void main(String[] args) {
        int result = Security.insertProviderAt(new BouncyCastleProvider(), 1);
        System.out.println("Insert BC: " + result);//NOSONAR

        System.out.println("Security providers:");//NOSONAR
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName() + ": " + provider.getInfo()); //NOSONAR
        }
        System.out.println();//NOSONAR

        System.out.println("Ciphers:");//NOSONAR
        for (String name : Security.getAlgorithms("cipher").stream().sorted().collect(Collectors.toList())) {
            System.out.println(name);//NOSONAR
        }
        System.out.println();//NOSONAR

        System.out.println("Random:");//NOSONAR
        for (String name : Security.getAlgorithms("securerandom").stream().sorted().collect(Collectors.toList())) {
            System.out.println(name);//NOSONAR
        }
        System.out.println();//NOSONAR
    }
}
