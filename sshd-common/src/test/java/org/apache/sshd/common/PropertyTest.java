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

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @param  <T> Type of property being tested
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class PropertyTest<T> extends JUnitTestSupport {
    private Property<T> prop;

    @SuppressWarnings("unchecked")
    void initPropertyTest(Class<T> propType, T defaultValue) throws Exception {
        String className = Property.class.getCanonicalName() + "$" + propType.getSimpleName() + "Property";
        Class<?> propClass = Class.forName(className);
        Constructor<?> ctor = propClass.getDeclaredConstructor(String.class, propType);
        prop = (Property<T>) ctor.newInstance(propClass.getSimpleName() + "Test", defaultValue);
    }

    static Collection<Object[]> parameters() {
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

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, default={1}")
    void propertyType(Class<T> propType, T defaultValue) throws Exception {
        initPropertyTest(propType, defaultValue);
        assertSame(propType, prop.getType());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, default={1}")
    void defaultValue(Class<T> propType, T defaultValue) throws Exception {
        initPropertyTest(propType, defaultValue);
        Optional<T> actual = prop.get(null);
        if (defaultValue == null) {
            assertFalse(actual.isPresent(), "Unexpected value: " + actual);
        } else {
            assertSame(defaultValue, actual.get());
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, default={1}")
    void getOrNullIfNoValueResolved(Class<T> propType, T defaultValue) throws Exception {
        initPropertyTest(propType, defaultValue);
        T actual = prop.getOrNull(PropertyResolver.EMPTY);
        assertNull(actual);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, default={1}")
    void getOrNullIfNoValueExists(Class<T> propType, T defaultValue) throws Exception {
        initPropertyTest(propType, defaultValue);
        T expected = getNonDefaultValue(propType);
        T actual = prop.getOrNull(asPropertyResolver(expected));
        assertSame(expected, actual);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, default={1}")
    void getOrCustomDefaultIfNoValueResolved(Class<T> propType, T defaultValue) throws Exception {
        initPropertyTest(propType, defaultValue);
        T expected = getCustomValue(propType);
        T actual = prop.getOrCustomDefault(PropertyResolver.EMPTY, expected);
        assertSame(expected, actual);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "type={0}, default={1}")
    void getOrCustomDefaultIfValueExists(Class<T> propType, T defaultValue) throws Exception {
        initPropertyTest(propType, defaultValue);
        T expected = getNonDefaultValue(propType);
        T actual = prop.getOrCustomDefault(asPropertyResolver(expected), getCustomValue(propType));
        assertSame(expected, actual);
    }

    private T getCustomValue(Class<T> propType) {
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

    private T getNonDefaultValue(Class<T> propType) {
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
