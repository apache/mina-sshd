/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util.security;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class SecurityProviderRegistrarCipherNameTest extends JUnitTestSupport {
    private CipherInformation cipherInfo;

    public void initSecurityProviderRegistrarCipherNameTest(CipherInformation cipherInfo) {
        this.cipherInfo = cipherInfo;
    }

    public static List<Object[]> parameters() {
        List<Object[]> params = new ArrayList<>();
        for (CipherInformation cipherInfo : BuiltinCiphers.VALUES) {
            String algorithm = cipherInfo.getAlgorithm();
            String xform = cipherInfo.getTransformation();
            if (!xform.startsWith(algorithm)) {
                continue;
            }

            params.add(new Object[] { cipherInfo });
        }
        return params;
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void getEffectiveSecurityEntityName(CipherInformation cipherInfo) {
        initSecurityProviderRegistrarCipherNameTest(cipherInfo);
        String expected = cipherInfo.getAlgorithm();
        String actual = SecurityProviderRegistrar.getEffectiveSecurityEntityName(Cipher.class, cipherInfo.getTransformation());
        assertEquals(expected, actual, "Mismatched pure cipher name");
    }
}
