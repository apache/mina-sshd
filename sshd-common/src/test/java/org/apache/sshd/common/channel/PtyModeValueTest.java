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

package org.apache.sshd.common.channel;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class PtyModeValueTest extends JUnitTestSupport {

    static Collection<PtyMode> parameters() {
        return PtyMode.MODES;
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void opcodeExtractor(PtyMode expected) {
        assertEquals(expected.toInt(), PtyMode.OPCODE_EXTRACTOR.applyAsInt(expected));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void byOpcodeComparator(PtyMode expected) {
        int v1 = expected.toInt();
        for (PtyMode actual : PtyMode.MODES) {
            int v2 = actual.toInt();
            int cmpExpected = Integer.signum(Integer.compare(v1, v2));
            int cmpActual = Integer.signum(PtyMode.BY_OPCODE.compare(expected, actual));
            assertEquals(cmpExpected, cmpActual, expected + " vs. " + actual);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fromName(PtyMode expected) {
        String name = expected.name();
        for (int index = 0; index < Byte.SIZE; index++) {
            PtyMode actual = PtyMode.fromName(name);
            assertSame(expected, actual, name);
            name = shuffleCase(name);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    @SuppressWarnings("unchecked")
    void getBooleanSettingValueOnNullOrEmptyValues(PtyMode expected) {
        for (Map<PtyMode, ?> modes : new Map[] { null, Collections.emptyMap() }) {
            String s = (modes == null) ? "null" : "empty";
            assertFalse(PtyMode.getBooleanSettingValue(modes, expected), "Map is " + s);
        }
    }
}
