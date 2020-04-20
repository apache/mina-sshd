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

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.BeforeClass;
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
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class KeyUtilsFingerprintCaseSensitivityTest extends JUnitTestSupport {

    // CHECKSTYLE:OFF
    private static final String KEY_STRING =
        "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAxr3N5fkt966xJINl0hH7Q6lLDRR1D0yMjcXCE5roE9VFut2ctGFuo90TCOxkPOMnwzwConeySc"
        + "VF4ConZeWsxbG9VtRh61IeZ6R5P5ZTvE9xPdZBgIEWvU1bRfrrOfSMihqF98pODspE6NoTtND2eglwSGwxcYFmpdTAmu+8qgxgGxlEaaCjqwd"
        + "iNPZhygrH81Mv2ruolNeZkn4Bj+wFFmZTD/waN1pQaMf+SO1+kEYIYFNl5+8JRGuUcr8MhHHJB+gwqMTF2BSBVITJzZUiQR0TMtkK6Vbs7yt1"
        + "F9hhzDzAFDwhV+rsfNQaOHpl3zP07qH+/99A0XG1CVcEdHqVMw== lgoldstein@LGOLDSTEIN-WIN7";
    // CHECKSTYLE:ON
    private static final String MD5_PREFIX = "MD5:";
    private static final String MD5 = "24:32:3c:80:01:b3:e1:fa:7c:53:ca:e3:e8:4e:c6:8e";
    private static final String MD5_FULL = MD5_PREFIX + MD5;
    private static final String SHA1_PREFIX = "SHA1:";
    private static final String SHA1 = "ZNLzC6u+F37oq8BpEAwP69EQtoA";
    private static final String SHA1_FULL = SHA1_PREFIX + SHA1;

    private static PublicKey key;

    private String expected;
    private String test;

    public KeyUtilsFingerprintCaseSensitivityTest(String expected, String test) {
        this.expected = expected;
        this.test = test;
    }

    @BeforeClass
    public static void beforeClass() throws GeneralSecurityException, IOException {
        PublicKeyEntry keyEntry = PublicKeyEntry.parsePublicKeyEntry(KEY_STRING);
        key = keyEntry.resolvePublicKey(null, Collections.emptyMap(), PublicKeyEntryResolver.FAILING);
    }

    @Parameters(name = "expected={0}, test={1}")
    public static Collection<Object[]> parameters() {
        return Arrays.asList(
                new Object[] { MD5_FULL, MD5_FULL },
                new Object[] { MD5_FULL, MD5_FULL.toUpperCase() },
                new Object[] { MD5_FULL, MD5_FULL.toLowerCase() },
                new Object[] { MD5_FULL, MD5_PREFIX.toUpperCase() + MD5 },
                new Object[] { MD5_FULL, MD5_PREFIX.toLowerCase() + MD5 },
                new Object[] { MD5_FULL, MD5.toLowerCase() },
                new Object[] { MD5_FULL, MD5.toUpperCase() },
                new Object[] { SHA1_FULL, SHA1_FULL },
                new Object[] { SHA1_FULL, SHA1_PREFIX.toUpperCase() + SHA1 },
                new Object[] { SHA1_FULL, SHA1_PREFIX.toLowerCase() + SHA1 });
    }

    @Test
    public void testCase() throws Exception {
        assertEquals("Check failed", new SimpleImmutableEntry<>(true, expected), KeyUtils.checkFingerPrint(test, key));
    }
}
