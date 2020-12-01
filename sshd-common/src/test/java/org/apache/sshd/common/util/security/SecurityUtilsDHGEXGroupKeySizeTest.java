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

import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.After;
import org.junit.Before;
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
public class SecurityUtilsDHGEXGroupKeySizeTest extends SecurityUtilsTestSupport {
    private final int expected;

    public SecurityUtilsDHGEXGroupKeySizeTest(int expected) {
        this.expected = expected;
    }

    @Before
    @After
    public void resetDHGEXGroupKeySizes() {
        System.clearProperty(SecurityUtils.MIN_DHGEX_KEY_SIZE_PROP);
        SecurityUtils.setMinDHGroupExchangeKeySize(0); // force detection
        System.clearProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP);
        SecurityUtils.setMaxDHGroupExchangeKeySize(0); // force detection
    }

    @Parameters(name = "keySize={0}")
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

    @Test
    public void testSetMaxDHGroupExchangeKeySizeByProperty() {
        System.setProperty(SecurityUtils.MAX_DHGEX_KEY_SIZE_PROP, Integer.toString(expected));
        assertTrue("DH group not supported for key size=" + expected, SecurityUtils.isDHGroupExchangeSupported());
        assertEquals("Mismatched values", expected, SecurityUtils.getMaxDHGroupExchangeKeySize());
    }

    @Test
    public void testSetMaxDHGroupExchangeKeySizeProgrammatically() {
        SecurityUtils.setMaxDHGroupExchangeKeySize(expected);
        assertTrue("DH group not supported for key size=" + expected, SecurityUtils.isDHGroupExchangeSupported());
        assertEquals("Mismatched values", expected, SecurityUtils.getMaxDHGroupExchangeKeySize());
    }

    @Test
    public void testSetMinDHGroupExchangeKeySizeByProperty() {
        System.setProperty(SecurityUtils.MIN_DHGEX_KEY_SIZE_PROP, Integer.toString(expected));
        assertTrue("DH group not supported for key size=" + expected, SecurityUtils.isDHGroupExchangeSupported());
        assertEquals("Mismatched values", expected, SecurityUtils.getMinDHGroupExchangeKeySize());
    }

    @Test
    public void testSetMinDHGroupExchangeKeySizeProgrammatically() {
        SecurityUtils.setMinDHGroupExchangeKeySize(expected);
        assertTrue("DH group not supported for key size=" + expected, SecurityUtils.isDHGroupExchangeSupported());
        assertEquals("Mismatched values", expected, SecurityUtils.getMinDHGroupExchangeKeySize());
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[keySize=" + expected + "]";
    }
}
