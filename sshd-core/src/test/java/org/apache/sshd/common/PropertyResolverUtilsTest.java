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

import java.util.Collection;
import java.util.Date;
import java.util.EnumSet;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class PropertyResolverUtilsTest extends JUnitTestSupport {
    public PropertyResolverUtilsTest() {
        super();
    }

    @Test
    void resolveAndUpdateClosestPropertyValue() {
        String propName = getCurrentTestName();
        String rootValue = getClass().getPackage().getName();
        Session resolver = createMockSession();
        FactoryManager root = Objects.requireNonNull(resolver.getFactoryManager(), "No manager");
        assertNull(PropertyResolverUtils.updateProperty(root, propName, rootValue), "Unexpected root previous value");
        assertSame(rootValue, PropertyResolverUtils.getString(resolver, propName), "Mismatched root value");

        String nodeValue = getClass().getSimpleName();
        assertNull(PropertyResolverUtils.updateProperty(resolver, propName, nodeValue), "Unexpected node previous value");
        assertSame(nodeValue, PropertyResolverUtils.getString(resolver, propName), "Mismatched node value");
    }

    @Test
    void syspropsResolver() {
        PropertyResolver resolver = SyspropsMapWrapper.SYSPROPS_RESOLVER;
        Map<String, ?> props = resolver.getProperties();
        assertTrue(MapEntryUtils.isEmpty(props), "Unexpected initial resolver values: " + props);

        final String propName = getCurrentTestName();
        assertNull(PropertyResolverUtils.getObject(resolver, propName), "Unexpected initial resolved value");

        final String propKey = SyspropsMapWrapper.getMappedSyspropKey(propName);
        assertNull(System.getProperty(propKey), "Unexpected property value for " + propKey);

        try {
            long expected = System.currentTimeMillis();
            System.setProperty(propKey, Long.toString(expected));
            testLongProperty(resolver, propName, expected);
        } finally {
            System.clearProperty(propKey);
        }

        try {
            int expected = 3777347;
            System.setProperty(propKey, Integer.toString(expected));
            testIntegerProperty(resolver, propName, expected);
        } finally {
            System.clearProperty(propKey);
        }

        for (boolean expected : new boolean[] { false, true }) {
            try {
                System.setProperty(propKey, Boolean.toString(expected));
                testBooleanProperty(resolver, propName, expected);
            } finally {
                System.clearProperty(propKey);
            }
        }
    }

    @Test
    void longProperty() {
        long expected = System.currentTimeMillis();
        String name = getCurrentTestName();

        Session session = createMockSession();
        assertEquals(expected, PropertyResolverUtils.getLongProperty(session, name, expected), "Mismatched empty props value");

        PropertyResolverUtils.updateProperty(session, name, expected);
        testLongProperty(session, name, expected);

        PropertyResolverUtils.updateProperty(session, name, Long.toString(expected));
        testLongProperty(session, name, expected);
    }

    @SuppressWarnings("checkstyle:avoidnestedblocks")
    private void testLongProperty(PropertyResolver resolver, String name, long expected) {
        Map<String, ?> props = resolver.getProperties();
        Object value = props.get(name);
        Class<?> type = value.getClass();
        String storage = type.getSimpleName();

        {
            Long actual = PropertyResolverUtils.getLong(resolver, name);
            assertNotNull(actual, "No actual Long value found for storage as " + storage);
            assertEquals(expected, actual.longValue(), "Mismatched values on Long retrieval for storage as " + storage);
        }

        {
            String actual = PropertyResolverUtils.getString(resolver, name);
            assertNotNull(actual, "No actual String value found for storage as " + storage);
            assertEquals(Long.toString(expected), actual, "Mismatched values on String retrieval for storage as " + storage);
        }
    }

    @Test
    void integerProperty() {
        int expected = 3777347;
        String name = getCurrentTestName();

        Session session = createMockSession();
        assertEquals(expected, PropertyResolverUtils.getIntProperty(session, name, expected), "Mismatched empty props value");

        PropertyResolverUtils.updateProperty(session, name, expected);
        testIntegerProperty(session, name, expected);

        PropertyResolverUtils.updateProperty(session, name, Integer.toString(expected));
        testIntegerProperty(session, name, expected);

        // store as Long but retrieve as Integer
        PropertyResolverUtils.updateProperty(session, name, Long.valueOf(expected));
        testIntegerProperty(session, name, expected);
    }

    @SuppressWarnings("checkstyle:avoidnestedblocks")
    private void testIntegerProperty(PropertyResolver resolver, String name, int expected) {
        Map<String, ?> props = resolver.getProperties();
        Object value = props.get(name);
        Class<?> type = value.getClass();
        String storage = type.getSimpleName();

        {
            Integer actual = PropertyResolverUtils.getInteger(resolver, name);
            assertNotNull(actual, "No actual Integer value found for storage as " + storage);
            assertEquals(expected, actual.intValue(), "Mismatched values on Integer retrieval for storage as " + storage);
        }

        {
            String actual = PropertyResolverUtils.getString(resolver, name);
            assertNotNull(actual, "No actual String value found for storage as " + storage);
            assertEquals(Integer.toString(expected), actual, "Mismatched values on String retrieval for storage as " + storage);
        }
    }

    @Test
    void booleanProperty() {
        for (boolean expected : new boolean[] { false, true }) {
            String name = getCurrentTestName();

            Session session = createMockSession();
            assertEquals("Mismatched empty props value", expected,
                    PropertyResolverUtils.getBooleanProperty(session, name, expected));

            PropertyResolverUtils.updateProperty(session, name, expected);
            testBooleanProperty(session, name, expected);

            PropertyResolverUtils.updateProperty(session, name, Boolean.toString(expected));
            testBooleanProperty(session, name, expected);
        }
    }

    @SuppressWarnings("checkstyle:avoidnestedblocks")
    private void testBooleanProperty(PropertyResolver resolver, String name, boolean expected) {
        Map<String, ?> props = resolver.getProperties();
        Object value = props.get(name);
        Class<?> type = value.getClass();
        String storage = type.getSimpleName();

        {
            Boolean actual = PropertyResolverUtils.getBoolean(resolver, name);
            assertNotNull(actual, "No actual Boolean value found for storage as " + storage);
            assertEquals("Mismatched values on Boolean retrieval for storage as " + storage, expected, actual.booleanValue());
        }

        {
            String actual = PropertyResolverUtils.getString(resolver, name);
            assertNotNull(actual, "No actual String value found for storage as " + storage);
            assertEquals(Boolean.toString(expected), actual, "Mismatched values on String retrieval for storage as " + storage);
        }
    }

    @Test
    void toEnumFromString() {
        Collection<TimeUnit> units = EnumSet.allOf(TimeUnit.class);
        for (TimeUnit expected : units) {
            String name = expected.name();
            for (int index = 1, count = name.length(); index <= count; index++) {
                TimeUnit actual = PropertyResolverUtils.toEnum(TimeUnit.class, name, true, units);
                assertSame(expected, actual, "Mismatched instance for name=" + name);
                name = shuffleCase(name);
            }
        }
    }

    @Test
    void toEnumFromEnum() {
        Collection<TimeUnit> units = EnumSet.allOf(TimeUnit.class);
        for (TimeUnit expected : units) {
            TimeUnit actual = PropertyResolverUtils.toEnum(TimeUnit.class, expected, true, null);
            assertSame(expected, actual, "Mismatched resolved value");
        }
    }

    @Test
    void toEnumFromNonString() {
        Collection<TimeUnit> units = EnumSet.allOf(TimeUnit.class);
        for (Object value : new Object[] { this, getClass(), new Date() }) {
            try {
                TimeUnit unit = PropertyResolverUtils.toEnum(TimeUnit.class, value, false, units);
                fail("Unexpected success for value=" + value + ": " + unit);
            } catch (IllegalArgumentException e) {
                // expected - ignored
            }
        }
    }

    @Test
    void toEnumNoMatchFound() {
        assertThrows(NoSuchElementException.class, () -> {
            TimeUnit result
                    = PropertyResolverUtils.toEnum(TimeUnit.class, getCurrentTestName(), true, EnumSet.allOf(TimeUnit.class));
            fail("Unexpected success: " + result);
        });
    }

    private Session createMockSession() {
        Map<String, Object> managerProps = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        FactoryManager manager = Mockito.mock(FactoryManager.class);
        Mockito.when(manager.getProperties()).thenReturn(managerProps);
        Mockito.when(manager.getParentPropertyResolver()).thenReturn(null);

        Map<String, Object> sessionProps = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Session session = Mockito.mock(Session.class);
        Mockito.when(session.getUsername()).thenReturn(getCurrentTestName());
        Mockito.when(session.getFactoryManager()).thenReturn(manager);
        Mockito.when(session.getParentPropertyResolver()).thenReturn(manager);
        Mockito.when(session.getProperties()).thenReturn(sessionProps);

        return session;
    }
}
