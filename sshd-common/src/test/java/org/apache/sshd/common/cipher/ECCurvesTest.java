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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ECCurvesTest extends JUnitTestSupport {
    public ECCurvesTest() {
        super();
    }

    @Test
    void fromName() {
        for (ECCurves expected : ECCurves.VALUES) {
            String name = expected.getName();
            for (int index = 0; index < name.length(); index++) {
                ECCurves actual = ECCurves.fromCurveName(name);
                assertSame(expected, actual, name);
                name = shuffleCase(name);
            }
        }
    }

    @Test
    void allNamesListed() {
        Set<ECCurves> listed = EnumSet.noneOf(ECCurves.class);
        for (String name : ECCurves.NAMES) {
            ECCurves c = ECCurves.fromCurveName(name);
            assertNotNull(c, "No curve for listed name=" + name);
            assertTrue(listed.add(c), "Duplicated listed name: " + name);
        }

        assertEquals("Mismatched listed vs. values", ECCurves.VALUES, listed);
    }

    @Test
    void fromKeySize() {
        for (ECCurves expected : ECCurves.VALUES) {
            String name = expected.getName();
            ECCurves actual = ECCurves.fromCurveSize(expected.getKeySize());
            assertSame(expected, actual, name);
        }
    }

    @Test
    void fromCurveParameters() {
        for (ECCurves expected : ECCurves.VALUES) {
            String name = expected.getName();
            ECCurves actual = ECCurves.fromCurveParameters(expected.getParameters());
            assertSame(expected, actual, name);
        }
    }

    @Test
    void fromKeyType() {
        for (ECCurves expected : ECCurves.VALUES) {
            String keyType = expected.getKeyType();
            for (int index = 0; index < keyType.length(); index++) {
                ECCurves actual = ECCurves.fromKeyType(keyType);
                assertSame(expected, actual, keyType);
                keyType = shuffleCase(keyType);
            }
        }
    }

    @Test
    void allKeyTypesListed() {
        Set<ECCurves> listed = EnumSet.noneOf(ECCurves.class);
        for (String name : ECCurves.KEY_TYPES) {
            ECCurves c = ECCurves.fromKeyType(name);
            assertNotNull(c, "No curve for listed key type=" + name);
            assertTrue(listed.add(c), "Duplicated listed key type: " + name);
        }

        assertEquals("Mismatched listed vs. values", ECCurves.VALUES, listed);
    }
}
