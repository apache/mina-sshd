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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
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
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class PtyModeValueTest extends JUnitTestSupport {
    private final PtyMode expected;

    public PtyModeValueTest(PtyMode expected) {
        this.expected = expected;
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(PtyMode.MODES);
    }

    @Test
    public void testOpcodeExtractor() {
        assertEquals(expected.toInt(), PtyMode.OPCODE_EXTRACTOR.applyAsInt(expected));
    }

    @Test
    public void testByOpcodeComparator() {
        int v1 = expected.toInt();
        for (PtyMode actual : PtyMode.MODES) {
            int v2 = actual.toInt();
            int cmpExpected = Integer.signum(Integer.compare(v1, v2));
            int cmpActual = Integer.signum(PtyMode.BY_OPCODE.compare(expected, actual));
            assertEquals(expected + " vs. " + actual, cmpExpected, cmpActual);
        }
    }

    @Test
    public void testFromName() {
        String name = expected.name();
        for (int index = 0; index < Byte.SIZE; index++) {
            PtyMode actual = PtyMode.fromName(name);
            assertSame(name, expected, actual);
            name = shuffleCase(name);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testGetBooleanSettingValueOnNullOrEmptyValues() {
        for (Map<PtyMode, ?> modes : new Map[] { null, Collections.emptyMap() }) {
            String s = (modes == null) ? "null" : "empty";
            assertFalse("Map is " + s, PtyMode.getBooleanSettingValue(modes, expected));
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + expected + "]";
    }
}
