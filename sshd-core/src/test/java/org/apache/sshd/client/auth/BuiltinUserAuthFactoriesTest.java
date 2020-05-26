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
package org.apache.sshd.client.auth;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

import org.apache.sshd.client.auth.BuiltinUserAuthFactories.ParseResult;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
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
public class BuiltinUserAuthFactoriesTest extends BaseTestSupport {
    private final BuiltinUserAuthFactories factory;

    public BuiltinUserAuthFactoriesTest(BuiltinUserAuthFactories factory) {
        this.factory = factory;
    }

    @Parameters(name = "Factory={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(BuiltinUserAuthFactories.VALUES);
    }

    @BeforeClass
    public static void testAllConstantsCovered() throws Exception {
        Field[] fields = UserAuthMethodFactory.class.getDeclaredFields();
        Collection<String> factories = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

        for (Field f : fields) {
            if (f.getType() != String.class) {
                continue;
            }

            int mods = f.getModifiers();
            if ((!Modifier.isStatic(mods)) || (!Modifier.isFinal(mods)) || (!Modifier.isPublic(mods))) {
                continue;
            }

            String name = Objects.toString(f.get(null), null);
            UserAuthFactory factory = BuiltinUserAuthFactories.fromFactoryName(name);
            if (factory == null) {
                continue;
            }

            assertTrue("Duplicate factory name constant: " + name, factories.add(name));
        }

        assertEquals("Mismatched factories names count: " + factories, factories.size(),
                BuiltinUserAuthFactories.VALUES.size());
    }

    @Test
    public void testSingletonFactoryInstance() {
        UserAuthFactory expected = factory.create();
        for (int index = 1; index <= Byte.SIZE; index++) {
            assertSame("Mismatched factory instance at invocation #" + index, expected, factory.create());
        }
    }

    @Test
    public void testFromFactoryName() {
        String name = factory.getName();
        UserAuthFactory expected = factory.create();
        for (int index = 1, count = name.length(); index <= count; index++) {
            UserAuthFactory actual = BuiltinUserAuthFactories.fromFactoryName(name);
            assertSame("Mismatched factory instance for name=" + name, expected, actual);
            name = shuffleCase(name); // prepare for next iteration
        }
    }

    @Test
    public void testParseResult() {
        ParseResult result = BuiltinUserAuthFactories.parseFactoriesList(factory.getName());
        assertNotNull("No parse result", result);

        List<UserAuthFactory> parsed = result.getParsedFactories();
        assertEquals("Mismatched parsed count", 1, GenericUtils.size(parsed));
        assertSame("Mismatched parsed factory instance", factory.create(), parsed.get(0));

        Collection<String> unsupported = result.getUnsupportedFactories();
        assertTrue("Unexpected unsupported values: " + unsupported, GenericUtils.isEmpty(unsupported));
    }
}
