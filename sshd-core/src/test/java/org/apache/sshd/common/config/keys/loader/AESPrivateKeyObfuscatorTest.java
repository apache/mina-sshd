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
package org.apache.sshd.common.config.keys.loader;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class)   // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class AESPrivateKeyObfuscatorTest extends BaseTestSupport {
    private static final Random RANDOMIZER = new Random(System.currentTimeMillis());

    private final int keyLength;

    public AESPrivateKeyObfuscatorTest(int keyLength) {
        this.keyLength = keyLength;
    }

    @Parameters(name = "keyLength={0}")
    public static List<Object[]> parameters() {
        List<Integer> lengths = AESPrivateKeyObfuscator.getAvailableKeyLengths();
        assertFalse("No lengths available", GenericUtils.isEmpty(lengths));
        return parameterize(lengths);
    }

    @Test
    public void testAvailableKeyLengthExists() throws GeneralSecurityException {
        assertEquals("Not a BYTE size multiple", 0, keyLength % Byte.SIZE);

        byte[] iv = new byte[keyLength / Byte.SIZE];
        synchronized (RANDOMIZER) {
            RANDOMIZER.nextBytes(iv);
        }

        Key key = new SecretKeySpec(iv, AESPrivateKeyObfuscator.CIPHER_NAME);
        Cipher c = SecurityUtils.getCipher(AESPrivateKeyObfuscator.CIPHER_NAME);
        c.init(Cipher.DECRYPT_MODE, key);
    }
}
