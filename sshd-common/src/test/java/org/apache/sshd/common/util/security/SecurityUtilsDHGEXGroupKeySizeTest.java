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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class SecurityUtilsDHGEXGroupKeySizeTest extends SecurityUtilsTestSupport {
    private int expected;

    public void initSecurityUtilsDHGEXGroupKeySizeTest(int expected) {
        this.expected = expected;
    }

    @BeforeEach
    @AfterEach
    void resetDHGEXGroupKeySizes() {
        System.clearProperty(SecurityUtils.MIN_DHGEX_KEY_SIZE_PROP);
        SecurityUtils.setMinDHGroupExchangeKeySize(0); // force detection
        System.clearProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP);
        SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
    }

    public static List<Object[]> parameters() {
        System.clearProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP);
        SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
        try {
            List<Object[]> values = new ArrayList<>();
            int maxSupported = SecurityUtils.getMaxDHGroupExchangeKeySize();
            for (int expected = SecurityUtils.MIN_DHGEX_KEY_SIZE;
                 expected <= maxSupported;
                 expected += 1024) {
                values.add(new Object[] { expected });
            }
            return values;
        } finally {
            SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "keySize={0}")
    public void setMaxDHGroupExchangeKeySizeByProperty(int expected) {
        initSecurityUtilsDHGEXGroupKeySizeTest(expected);
        System.setProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP, Integer.toString(expected));
        assertTrue(SecurityUtils.isDHGroupExchangeSupported(), "DH group not supported for key size=" + expected);
        assertEquals(expected, SecurityUtils.getMaxDHGroupExchangeKeySize(), "Mismatched values");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "keySize={0}")
    public void setMaxDHGroupExchangeKeySizeProgrammatically(int expected) {
        initSecurityUtilsDHGEXGroupKeySizeTest(expected);
        SecurityUtils.setMaxDHGroupExchangeKeySize(expected);
        assertTrue(SecurityUtils.isDHGroupExchangeSupported(), "DH group not supported for key size=" + expected);
        assertEquals(expected, SecurityUtils.getMaxDHGroupExchangeKeySize(), "Mismatched values");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "keySize={0}")
    public void setMinDHGroupExchangeKeySizeByProperty(int expected) {
        initSecurityUtilsDHGEXGroupKeySizeTest(expected);
        System.setProperty(SecurityUtils.MIN_DHGEX_KEY_SIZE_PROP, Integer.toString(expected));
        assertTrue(SecurityUtils.isDHGroupExchangeSupported(), "DH group not supported for key size=" + expected);
        assertEquals(expected, SecurityUtils.getMinDHGroupExchangeKeySize(), "Mismatched values");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "keySize={0}")
    public void setMinDHGroupExchangeKeySizeProgrammatically(int expected) {
        initSecurityUtilsDHGEXGroupKeySizeTest(expected);
        SecurityUtils.setMinDHGroupExchangeKeySize(expected);
        assertTrue(SecurityUtils.isDHGroupExchangeSupported(), "DH group not supported for key size=" + expected);
        assertEquals(expected, SecurityUtils.getMinDHGroupExchangeKeySize(), "Mismatched values");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[keySize=" + expected + "]";
    }
}
