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

import java.util.Map;
import java.util.TreeMap;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PropertyResolverUtilsTest extends BaseTestSupport {
    public PropertyResolverUtilsTest() {
        super();
    }

    @Test
    public void testResolveAndUpdateClosestPropertyValue() {
        final String propName = getCurrentTestName();
        final String rootValue = getClass().getPackage().getName();
        Session resolver = createMockSession();
        FactoryManager root = ValidateUtils.checkNotNull(resolver.getFactoryManager(), "No manager");
        assertNull("Unexpected root previous value", PropertyResolverUtils.updateProperty(root, propName, rootValue));
        assertSame("Mismatched root value", rootValue, PropertyResolverUtils.getString(resolver, propName));

        final String nodeValue = getClass().getSimpleName();
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

        for (final boolean expected : new boolean[]{false, true}) {
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
        final long expected = System.currentTimeMillis();
        final String name = getCurrentTestName();

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
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Long.toString(expected), actual.toString());
        }
    }

    @Test
    public void testIntegerProperty() {
        final int expected = 3777347;
        final String name = getCurrentTestName();

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
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Integer.toString(expected), actual.toString());
        }
    }

    @Test
    public void testBooleanProperty() {
        for (final boolean expected : new boolean[]{false, true}) {
            final String name = getCurrentTestName();

            Session session = createMockSession();
            assertEquals("Mismatched empty props value", expected, PropertyResolverUtils.getBooleanProperty(session, name, expected));

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
            assertEquals("Mismatched values on String retrieval for storage as " + storage, Boolean.toString(expected), actual.toString());
        }
    }

    private Session createMockSession() {
        Map<String, Object> managerProps = new TreeMap<String, Object>(String.CASE_INSENSITIVE_ORDER);
        FactoryManager manager = Mockito.mock(FactoryManager.class);
        Mockito.when(manager.getProperties()).thenReturn(managerProps);
        Mockito.when(manager.getParentPropertyResolver()).thenReturn(null);

        Map<String, Object> sessionProps = new TreeMap<String, Object>(String.CASE_INSENSITIVE_ORDER);
        Session session = Mockito.mock(Session.class);
        Mockito.when(session.getUsername()).thenReturn(getCurrentTestName());
        Mockito.when(session.getFactoryManager()).thenReturn(manager);
        Mockito.when(session.getParentPropertyResolver()).thenReturn(manager);
        Mockito.when(session.getProperties()).thenReturn(sessionProps);

        return session;
    }
}
