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
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class PropertyResolverUtilsTest extends JUnitTestSupport {
    public PropertyResolverUtilsTest() {
        super();
    }

    @Test
    public void testResolveAndUpdateClosestPropertyValue() {
        String propName = getCurrentTestName();
        String rootValue = getClass().getPackage().getName();
        Session resolver = createMockSession();
        FactoryManager root = Objects.requireNonNull(resolver.getFactoryManager(), "No manager");
        assertNull("Unexpected root previous value", PropertyResolverUtils.updateProperty(root, propName, rootValue));
        assertSame("Mismatched root value", rootValue, PropertyResolverUtils.getString(resolver, propName));

        String nodeValue = getClass().getSimpleName();
        assertNull("Unexpected node previous value", PropertyResolverUtils.updateProperty(resolver, propName, nodeValue));
        assertSame("Mismatched node value", nodeValue, PropertyResolverUtils.getString(resolver, propName));
    }

    @Test
    public void testSyspropsResolver() {
        PropertyResolver resolver = SyspropsMapWrapper.SYSPROPS_RESOLVER;
        Map<String, ?> props = resolver.getProperties();
        assertTrue("Unexpected initial resolver values: " + props, GenericUtils.isEmpty(props));

        final String propName = getCurrentTestName();
        assertNull("Unexpected initial resolved value", PropertyResolverUtils.getObject(resolver, propName));

        final String propKey = SyspropsMapWrapper.getMappedSyspropKey(propName);
        assertNull("Unexpected property value for " + propKey, System.getProperty(propKey));

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
    public void testLongProperty() {
        long expected = System.currentTimeMillis();
        String name = getCurrentTestName();

        Session session = createMockSession();
        assertEquals("Mismatched empty props value", expected, PropertyResolverUtils.getLongProperty(session, name, expected));

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
            assertNotNull("No actual Long value found for storage as " + storage, actual);
            assertEquals("Mismatched values on Long retrieval for storage as " + storage, expected, actual.longValue());
        }

        {
            String actual = PropertyResolverUtils.getString(resolver, name);
            assertNotNull("No actual String value found for storage as " + storage, actual);
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Long.toString(expected), actual);
        }
    }

    @Test
    public void testIntegerProperty() {
        int expected = 3777347;
        String name = getCurrentTestName();

        Session session = createMockSession();
        assertEquals("Mismatched empty props value", expected, PropertyResolverUtils.getIntProperty(session, name, expected));

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
            assertNotNull("No actual Integer value found for storage as " + storage, actual);
            assertEquals("Mismatched values on Integer retrieval for storage as " + storage, expected, actual.intValue());
        }

        {
            String actual = PropertyResolverUtils.getString(resolver, name);
            assertNotNull("No actual String value found for storage as " + storage, actual);
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Integer.toString(expected), actual);
        }
    }

    @Test
    public void testBooleanProperty() {
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
            assertNotNull("No actual Boolean value found for storage as " + storage, actual);
            assertEquals("Mismatched values on Boolean retrieval for storage as " + storage, expected, actual.booleanValue());
        }

        {
            String actual = PropertyResolverUtils.getString(resolver, name);
            assertNotNull("No actual String value found for storage as " + storage, actual);
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Boolean.toString(expected), actual);
        }
    }

    @Test
    public void testToEnumFromString() {
        Collection<TimeUnit> units = EnumSet.allOf(TimeUnit.class);
        for (TimeUnit expected : units) {
            String name = expected.name();
            for (int index = 1, count = name.length(); index <= count; index++) {
                TimeUnit actual = PropertyResolverUtils.toEnum(TimeUnit.class, name, true, units);
                assertSame("Mismatched instance for name=" + name, expected, actual);
                name = shuffleCase(name);
            }
        }
    }

    @Test
    public void testToEnumFromEnum() {
        Collection<TimeUnit> units = EnumSet.allOf(TimeUnit.class);
        for (TimeUnit expected : units) {
            TimeUnit actual = PropertyResolverUtils.toEnum(TimeUnit.class, expected, true, null);
            assertSame("Mismatched resolved value", expected, actual);
        }
    }

    @Test
    public void testToEnumFromNonString() {
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

    @Test(expected = NoSuchElementException.class)
    public void testToEnumNoMatchFound() {
        TimeUnit result
                = PropertyResolverUtils.toEnum(TimeUnit.class, getCurrentTestName(), true, EnumSet.allOf(TimeUnit.class));
        fail("Unexpected success: " + result);
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
