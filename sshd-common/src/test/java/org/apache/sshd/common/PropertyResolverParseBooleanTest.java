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

package org.apache.sshd.common;

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class PropertyResolverParseBooleanTest extends JUnitTestSupport {

    public static List<Object[]> parameters() {
        List<Object[]> result = new ArrayList<>();
        result.add(new Object[] { null, null });
        result.add(new Object[] { "", null });
        for (String v : PropertyResolverUtils.TRUE_VALUES) {
            result.add(new Object[] { v, Boolean.TRUE });
        }

        for (String v : PropertyResolverUtils.FALSE_VALUES) {
            result.add(new Object[] { v, Boolean.FALSE });
        }
        return result;
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "value={0}, expected={1}")
    void simpleParseBoolean(String value, Boolean expected) {
        Boolean actual = PropertyResolverUtils.parseBoolean(value);
        assertSame(expected, actual);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "value={0}, expected={1}")
    void caseInsensitiveParseBoolean(String value, Boolean expected) {
        if (!GenericUtils.isEmpty(value)) {
            String v = value;
            for (int index = 1, count = v.length(); index <= (2 * count); index++) {
                v = shuffleCase(v);
                Boolean actual = PropertyResolverUtils.parseBoolean(v);
                assertSame(expected, actual, "Mismatched result for '" + v + "'");
            }
        }
    }
}
