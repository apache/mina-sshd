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

import java.lang.reflect.Constructor;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Map;
import java.util.Optional;

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
 * @param  <T> Type of property being tested
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class PropertyTest<T> extends JUnitTestSupport {
    private final Class<T> propType;
    private final T defaultValue;
    private final Property<T> prop;

    @SuppressWarnings("unchecked")
    public PropertyTest(Class<T> propType, T defaultValue) throws Exception {
        this.propType = propType;
        this.defaultValue = defaultValue;

        String className = Property.class.getCanonicalName() + "$" + propType.getSimpleName() + "Property";
        Class<?> propClass = Class.forName(className);
        Constructor<?> ctor = propClass.getDeclaredConstructor(String.class, propType);
        prop = (Property<T>) ctor.newInstance(propClass.getSimpleName() + "Test", defaultValue);
    }

    @Parameters(name = "type={0}, default={1}")
    public static Collection<Object[]> parameters() {
        Collection<Object[]> testCases = new LinkedList<>();
        testCases.add(new Object[] { Integer.class, null });
        testCases.add(new Object[] { Integer.class, 22 });
        testCases.add(new Object[] { Long.class, null });
        testCases.add(new Object[] { Long.class, 22L });
        testCases.add(new Object[] { String.class, null });
        testCases.add(new Object[] { String.class, "MINA-SSHD" });
        testCases.add(new Object[] { Boolean.class, null });
        testCases.add(new Object[] { Boolean.class, true });
        return testCases;
    }

    @Test
    public void testPropertyType() {
        assertSame(propType, prop.getType());
    }

    @Test
    public void testDefaultValue() {
        Optional<T> actual = prop.get(null);
        if (defaultValue == null) {
            assertFalse("Unexpected value: " + actual, actual.isPresent());
        } else {
            assertSame(defaultValue, actual.get());
        }
    }

    @Test
    public void testGetOrNullIfNoValueResolved() {
        T actual = prop.getOrNull(PropertyResolver.EMPTY);
        assertNull(actual);
    }

    @Test
    public void testGetOrNullIfNoValueExists() {
        T expected = getNonDefaultValue();
        T actual = prop.getOrNull(asPropertyResolver(expected));
        assertSame(expected, actual);
    }

    @Test
    public void testGetOrCustomDefaultIfNoValueResolved() {
        T expected = getCustomValue();
        T actual = prop.getOrCustomDefault(PropertyResolver.EMPTY, expected);
        assertSame(expected, actual);
    }

    @Test
    public void testGetOrCustomDefaultIfValueExists() {
        T expected = getNonDefaultValue();
        T actual = prop.getOrCustomDefault(asPropertyResolver(expected), getCustomValue());
        assertSame(expected, actual);
    }

    private T getCustomValue() {
        if (propType == Integer.class) {
            return propType.cast(33);
        } else if (propType == Long.class) {
            return propType.cast(33L);
        } else if (propType == String.class) {
            return propType.cast(getCurrentTestName());
        } else if (propType == Boolean.class) {
            return propType.cast(false);
        } else {
            throw new UnsupportedOperationException("Unsupported property type: " + propType.getSimpleName());
        }
    }

    private T getNonDefaultValue() {
        if (propType == Integer.class) {
            return propType.cast(44);
        } else if (propType == Long.class) {
            return propType.cast(44L);
        } else if (propType == String.class) {
            return propType.cast(getClass().getSimpleName());
        } else if (propType == Boolean.class) {
            return propType.cast(false);
        } else {
            throw new UnsupportedOperationException("Unsupported property type: " + propType.getSimpleName());
        }
    }

    private PropertyResolver asPropertyResolver(Object value) {
        return new PropertyResolver() {
            @SuppressWarnings("synthetic-access")
            private final Map<String, Object> props = Collections.singletonMap(prop.getName(), value);

            @Override
            public Map<String, Object> getProperties() {
                return props;
            }

            @Override
            public PropertyResolver getParentPropertyResolver() {
                return null;
            }
        };
    }
}
