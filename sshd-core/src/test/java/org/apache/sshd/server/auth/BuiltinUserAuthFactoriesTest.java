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
package org.apache.sshd.server.auth;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.auth.BuiltinUserAuthFactories.ParseResult;
import org.apache.sshd.server.auth.gss.UserAuthGSSFactory;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class BuiltinUserAuthFactoriesTest extends BaseTestSupport {
    private BuiltinUserAuthFactories factory;

    public void initBuiltinUserAuthFactoriesTest(BuiltinUserAuthFactories factory) {
        this.factory = factory;
    }

    public static Collection<Object[]> parameters() {
        return parameterize(BuiltinUserAuthFactories.VALUES);
    }

    @BeforeAll
    static void testAllConstantsCovered() throws Exception {
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

            assertTrue(factories.add(name), "Duplicate factory name constant: " + name);
        }

        assertTrue(factories.add(UserAuthGSSFactory.NAME), "Unexpected GSS name constant");
        assertEquals(factories.size(),
                BuiltinUserAuthFactories.VALUES.size(),
                "Mismatched factories names count: " + factories);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "Factory={0}")
    public void singletonFactoryInstance(BuiltinUserAuthFactories factory) {
        initBuiltinUserAuthFactoriesTest(factory);
        UserAuthFactory expected = factory.create();
        for (int index = 1; index <= Byte.SIZE; index++) {
            assertSame(expected, factory.create(), "Mismatched factory instance at invocation #" + index);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "Factory={0}")
    public void fromFactoryName(BuiltinUserAuthFactories factory) {
        initBuiltinUserAuthFactoriesTest(factory);
        String name = factory.getName();
        UserAuthFactory expected = factory.create();
        for (int index = 1, count = name.length(); index <= count; index++) {
            UserAuthFactory actual = BuiltinUserAuthFactories.fromFactoryName(name);
            assertSame(expected, actual, "Mismatched factory instance for name=" + name);
            name = shuffleCase(name); // prepare for next iteration
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "Factory={0}")
    public void parseResult(BuiltinUserAuthFactories factory) {
        initBuiltinUserAuthFactoriesTest(factory);
        ParseResult result = BuiltinUserAuthFactories.parseFactoriesList(factory.getName());
        assertNotNull(result, "No parse result");

        List<UserAuthFactory> parsed = result.getParsedFactories();
        assertEquals(1, GenericUtils.size(parsed), "Mismatched parsed count");
        assertSame(factory.create(), parsed.get(0), "Mismatched parsed factory instance");

        Collection<String> unsupported = result.getUnsupportedFactories();
        assertTrue(GenericUtils.isEmpty(unsupported), "Unexpected unsupported values: " + unsupported);
    }
}
