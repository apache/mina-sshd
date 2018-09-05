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

package org.apache.sshd.common.cipher;

import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class ECCurvesTest extends JUnitTestSupport {
    public ECCurvesTest() {
        super();
    }

    @Test
    public void testFromName() {
        for (ECCurves expected : ECCurves.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                ECCurves actual = ECCurves.fromCurveName(name);
                assertSame(name, expected, actual);
                name = shuffleCase(name);
            }
        }
    }

    @Test
    public void testAllNamesListed() {
        Set<ECCurves> listed = EnumSet.noneOf(ECCurves.class);
        for (String name : ECCurves.NAMES) {
            ECCurves c = ECCurves.fromCurveName(name);
            assertNotNull("No curve for listed name=" + name, c);
            assertTrue("Duplicated listed name: " + name, listed.add(c));
        }

        assertEquals("Mismatched listed vs. values", ECCurves.VALUES, listed);
    }

    @Test
    public void testFromKeySize() {
        for (ECCurves expected : ECCurves.VALUES) {
            String name = expected.getName();
            ECCurves actual = ECCurves.fromCurveSize(expected.getKeySize());
            assertSame(name, expected, actual);
        }
    }

    @Test
    public void testFromCurveParameters() {
        for (ECCurves expected : ECCurves.VALUES) {
            String name = expected.getName();
            ECCurves actual = ECCurves.fromCurveParameters(expected.getParameters());
            assertSame(name, expected, actual);
        }
    }

    @Test
    public void testFromKeyType() {
        for (ECCurves expected : ECCurves.VALUES) {
            String keyType = expected.getKeyType();
            for (int index = 0; index < keyType.length(); index++) {
                ECCurves actual = ECCurves.fromKeyType(keyType);
                assertSame(keyType, expected, actual);
                keyType = shuffleCase(keyType);
            }
        }
    }

    @Test
    public void testAllKeyTypesListed() {
        Set<ECCurves> listed = EnumSet.noneOf(ECCurves.class);
        for (String name : ECCurves.KEY_TYPES) {
            ECCurves c = ECCurves.fromKeyType(name);
            assertNotNull("No curve for listed key type=" + name, c);
            assertTrue("Duplicated listed key type: " + name, listed.add(c));
        }

        assertEquals("Mismatched listed vs. values", ECCurves.VALUES, listed);
    }
}
