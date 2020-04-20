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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
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
public class PropertyResolverParseBooleanTest extends JUnitTestSupport {
    private final String value;
    private final Boolean expected;

    public PropertyResolverParseBooleanTest(String value, Boolean expected) {
        this.value = value;
        this.expected = expected;
    }

    @Parameters(name = "value={0}, expected={1}")
    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                for (String v : new String[] { null, "" }) {
                    add(new Object[] { v, null });
                }

                for (String v : PropertyResolverUtils.TRUE_VALUES) {
                    add(new Object[] { v, Boolean.TRUE });
                }

                for (String v : PropertyResolverUtils.FALSE_VALUES) {
                    add(new Object[] { v, Boolean.FALSE });
                }
            }
        };
    }

    @Test
    public void testSimpleParseBoolean() {
        Boolean actual = PropertyResolverUtils.parseBoolean(value);
        assertSame(expected, actual);
    }

    @Test
    public void testCaseInsensitiveParseBoolean() {
        Assume.assumeFalse("Skip empty value", GenericUtils.isEmpty(value));

        String v = value;
        for (int index = 1, count = v.length(); index <= (2 * count); index++) {
            v = shuffleCase(v);
            Boolean actual = PropertyResolverUtils.parseBoolean(v);
            assertSame("Mismatched result for '" + v + "'", expected, actual);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + value + " => " + expected + "]";
    }
}
