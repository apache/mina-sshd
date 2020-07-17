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

import java.nio.charset.Charset;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.NavigableSet;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class PropertyResolverUtils {
    public static final String NONE_VALUE = "none";

    /**
     * Case <U>insensitive</U> {@link NavigableSet} of values considered {@code true} by {@link #parseBoolean(String)}
     */
    public static final NavigableSet<String> TRUE_VALUES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(
                    String.CASE_INSENSITIVE_ORDER, "true", "t", "yes", "y", "on"));

    /**
     * Case <U>insensitive</U> {@link NavigableSet} of values considered {@code false} by {@link #parseBoolean(String)}
     */
    public static final NavigableSet<String> FALSE_VALUES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(
                    String.CASE_INSENSITIVE_ORDER, "false", "f", "no", "n", "off"));

    private PropertyResolverUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @param  v Value to examine
     * @return   {@code true} if equals to {@value #NONE_VALUE} - case <U>insensitive</U>
     */
    public static boolean isNoneValue(String v) {
        return NONE_VALUE.equalsIgnoreCase(v);
    }

    /**
     * @param  resolver              The {@link PropertyResolver} instance - ignored if {@code null}
     * @param  name                  The property name
     * @param  defaultValue          The default value to return if the specified property does not exist in the
     *                               properties map
     * @return                       The resolved property
     * @throws NumberFormatException if malformed value
     * @see                          #toLong(Object, long)
     */
    public static long getLongProperty(PropertyResolver resolver, String name, long defaultValue) {
        return toLong(resolvePropertyValue(resolver, name), defaultValue);
    }

    public static long getLongProperty(Map<String, ?> props, String name, long defaultValue) {
        return toLong(resolvePropertyValue(props, name), defaultValue);
    }

    /**
     * Converts a generic object value to a {@code long} if possible:
     * <UL>
     * <LI>If value is {@code null} the default is returned</LI>
     *
     * <LI>If value is a {@link Number} then its {@link Number#longValue()} is returned</LI>
     *
     * <LI>Otherwise, the value's {@code toString()} is parsed as a {@code long}</LI>
     * </UL>
     *
     * @param  value                 The resolved value - may be {@code null}
     * @param  defaultValue          The default to use if {@code null} resolved value
     * @return                       The resolved value
     * @throws NumberFormatException if malformed value
     * @see                          Long#parseLong(String)
     */
    public static long toLong(Object value, long defaultValue) {
        if (value == null) {
            return defaultValue;
        } else if (value instanceof Number) {
            return ((Number) value).longValue();
        } else { // we parse the string in case it is not a valid long value
            return Long.parseLong(value.toString());
        }
    }

    /**
     * @param  resolver              The {@link PropertyResolver} instance - ignored if {@code null}
     * @param  name                  The property name
     * @return                       The {@link Long} value or {@code null} if property not found
     * @throws NumberFormatException if malformed value
     * @see                          #toLong(Object)
     */
    public static Long getLong(PropertyResolver resolver, String name) {
        return toLong(resolvePropertyValue(resolver, name));
    }

    public static Long getLong(Map<String, ?> props, String name) {
        return toLong(resolvePropertyValue(props, name));
    }

    /**
     * Converts a generic object into a {@link Long}:
     * <UL>
     * <LI>If the value is {@code null} then returns {@code null}.</LI>
     *
     * <LI>If the value is already a {@link Long} then it is returned as such.</LI>
     * 
     * <LI>If value is a {@link Number} then its {@link Number#longValue()} is wrapped as a {@link Long}</LI>
     *
     * <LI>Otherwise, the value's {@code toString()} is parsed as a {@link Long}</LI>
     * </UL>
     *
     * @param  value                 The resolved value - may be {@code null}
     * @return                       The {@link Long} value or {@code null} if property not found
     * @throws NumberFormatException if malformed value
     * @see                          Long#valueOf(long)
     * @see                          Long#valueOf(String)
     */
    public static Long toLong(Object value) {
        if (value == null) {
            return null;
        } else if (value instanceof Long) {
            return (Long) value;
        } else if (value instanceof Number) {
            return ((Number) value).longValue();
        } else { // we parse the string in case it is not a valid long value
            return Long.valueOf(value.toString());
        }
    }

    /**
     * Converts an enumerated configuration value:
     * <UL>
     * <P>
     * <LI>If value is {@code null} then return {@code null}</LI>
     * </P>
     *
     * <P>
     * <LI>If value already of the expected type then simply cast and return it.</LI>
     * </P>
     *
     * <P>
     * <LI>If value is a {@link CharSequence} then convert it to a string and look for a matching enumerated value name
     * - case <U>insensitive</U>.</LI>
     * </P>
     * >
     * </UL>
     *
     * @param  <E>                      Type of enumerated value
     * @param  enumType                 The enumerated class type
     * @param  value                    The configured value - ignored if {@code null}
     * @param  failIfNoMatch            Whether to fail if no matching name found
     * @param  available                The available values to compare the name
     * @return                          The matching enumerated value - {@code null} if no match found
     * @throws IllegalArgumentException If value is neither {@code null}, nor the enumerated type nor a
     *                                  {@link CharSequence}
     * @throws NoSuchElementException   If no matching string name found and <tt>failIfNoMatch</tt> is {@code true}
     */
    public static <E extends Enum<E>> E toEnum(
            Class<E> enumType, Object value, boolean failIfNoMatch, Collection<E> available) {
        if (value == null) {
            return null;
        } else if (enumType.isInstance(value)) {
            return enumType.cast(value);
        } else if (value instanceof CharSequence) {
            String name = value.toString();
            if (GenericUtils.size(available) > 0) {
                for (E v : available) {
                    if (name.equalsIgnoreCase(v.name())) {
                        return v;
                    }
                }
            }

            if (failIfNoMatch) {
                throw new NoSuchElementException("No match found for " + enumType.getSimpleName() + "[" + name + "]");
            }

            return null;
        } else {
            throw new IllegalArgumentException(
                    "Bad value type for enum conversion: " + value.getClass().getSimpleName());
        }
    }

    public static Object updateProperty(PropertyResolver resolver, String name, long value) {
        return updateProperty(resolver.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String, Object> props, String name, long value) {
        return updateProperty(props, name, Long.valueOf(value));
    }

    public static int getIntProperty(PropertyResolver resolver, String name, int defaultValue) {
        return toInteger(resolvePropertyValue(resolver, name), defaultValue);
    }

    public static int getIntProperty(Map<String, ?> props, String name, int defaultValue) {
        return toInteger(resolvePropertyValue(props, name), defaultValue);
    }

    public static int toInteger(Object value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } else { // we parse the string in case this is NOT an integer
            return Integer.parseInt(value.toString());
        }
    }

    public static Integer getInteger(PropertyResolver resolver, String name) {
        return toInteger(resolvePropertyValue(resolver, name));
    }

    public static Integer getInteger(Map<String, ?> props, String name) {
        return toInteger(resolvePropertyValue(props, name));
    }

    public static Integer toInteger(Object value) {
        if (value == null) {
            return null;
        } else if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } else { // we parse the string in case this is NOT a valid integer string
            return Integer.valueOf(value.toString());
        }
    }

    public static Object updateProperty(PropertyResolver resolver, String name, int value) {
        return updateProperty(resolver.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String, Object> props, String name, int value) {
        return updateProperty(props, name, Integer.valueOf(value));
    }

    public static boolean getBooleanProperty(PropertyResolver resolver, String name, boolean defaultValue) {
        return toBoolean(getObject(resolver, name), defaultValue);
    }

    public static boolean getBooleanProperty(Map<String, ?> props, String name, boolean defaultValue) {
        return toBoolean(getObject(props, name), defaultValue);
    }

    /**
     * @param  value        The value to convert
     * @param  defaultValue The default value to return if value is {@code null} or and empty string, then returns the
     *                      default value.
     * @return              The resolved value
     * @see                 #toBoolean(Object)
     */
    public static boolean toBoolean(Object value, boolean defaultValue) {
        Boolean bool = toBoolean(value);
        if (bool == null) {
            return defaultValue;
        } else {
            return bool;
        }
    }

    public static Boolean getBoolean(PropertyResolver resolver, String name) {
        Object propValue = resolvePropertyValue(resolver, name);
        return toBoolean(propValue);
    }

    public static Boolean getBoolean(Map<String, ?> props, String name) {
        Object propValue = resolvePropertyValue(props, name);
        return toBoolean(propValue);
    }

    /**
     * <P>
     * Attempts to convert the object into a {@link Boolean} value as follows:
     * </P>
     * </BR>
     * <UL>
     * <P>
     * <LI>If {@code null} or an empty string then return {@code null}.</LI>
     * </P>
     *
     * <P>
     * <LI>If already a {@link Boolean} then return as-is</LI>
     * </P>
     *
     * <P>
     * <LI>If a {@link CharSequence} then invoke {@link #parseBoolean(String)}</LI>
     * </P>
     *
     * <P>
     * <LI>Otherwise, throws an {@link UnsupportedOperationException}</LI>
     * </P>
     * </UL>
     * 
     * @param  value                         The value to be converted
     * @return                               The result - {@code null} if {@code null} or an empty string
     * @throws UnsupportedOperationException If value cannot be converted to a boolean - e.g., a number.
     * @see                                  #parseBoolean(String)
     */
    public static Boolean toBoolean(Object value) {
        if (value == null) {
            return null;
        } else if (value instanceof Boolean) {
            return (Boolean) value;
        } else if (value instanceof CharSequence) {
            return parseBoolean(value.toString());
        } else {
            throw new UnsupportedOperationException(
                    "Cannot convert " + value.getClass().getSimpleName() + "[" + value + "] to boolean");
        }
    }

    /**
     * Converts a string to a {@link Boolean} value by looking for it in either the {@link #TRUE_VALUES} or
     * {@link #FALSE_VALUES}
     *
     * @param  value                    The value to parse
     * @return                          The result - {@code null} if value is {@code null}/empty
     * @throws IllegalArgumentException If non-empty string that does not match (case <U>insensitive</U>) either of the
     *                                  known values for boolean.
     */
    public static Boolean parseBoolean(String value) {
        if (GenericUtils.isEmpty(value)) {
            return null;
        } else if (TRUE_VALUES.contains(value)) {
            return Boolean.TRUE;
        } else if (FALSE_VALUES.contains(value)) {
            return Boolean.FALSE;
        } else {
            throw new IllegalArgumentException("Unknown boolean value: '" + value + "'");
        }
    }

    public static Object updateProperty(PropertyResolver resolver, String name, boolean value) {
        return updateProperty(resolver.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String, Object> props, String name, boolean value) {
        return updateProperty(props, name, Boolean.valueOf(value));
    }

    /**
     * @param  resolver     The {@link PropertyResolver} to use - ignored if {@code null}
     * @param  name         The property name
     * @param  defaultValue The default value to return if property not set or empty
     * @return              The set value (if not {@code null}/empty) or default one
     */
    public static String getStringProperty(
            PropertyResolver resolver, String name, String defaultValue) {
        String value = getString(resolver, name);
        if (GenericUtils.isEmpty(value)) {
            return defaultValue;
        } else {
            return value;
        }
    }

    public static String getStringProperty(Map<String, ?> props, String name, String defaultValue) {
        Object value = resolvePropertyValue(props, name);
        if (value == null) {
            return defaultValue;
        } else {
            return Objects.toString(value);
        }
    }

    public static Charset getCharset(PropertyResolver resolver, String name, Charset defaultValue) {
        Object value = getObject(resolver, name);
        return (value == null) ? defaultValue : toCharset(value);
    }

    public static Charset getCharset(Map<String, ?> props, String name, Charset defaultValue) {
        Object value = getObject(props, name);
        return (value == null) ? defaultValue : toCharset(value);
    }

    public static Charset toCharset(Object value) {
        if (value == null) {
            return null;
        } else if (value instanceof Charset) {
            return (Charset) value;
        } else if (value instanceof CharSequence) {
            return Charset.forName(value.toString());
        } else {
            throw new IllegalArgumentException("Invalid charset conversion value: " + value);
        }
    }

    public static String getString(PropertyResolver resolver, String name) {
        Object value = getObject(resolver, name);
        return Objects.toString(value, null);
    }

    public static String getString(Map<String, ?> props, String name) {
        Object value = getObject(props, name);
        return Objects.toString(value, null);
    }

    public static Object getObject(PropertyResolver resolver, String name) {
        return resolvePropertyValue(resolver, name);
    }

    public static Object getObject(PropertyResolver resolver, String name, Object defaultValue) {
        Object value = resolvePropertyValue(resolver, name);
        return value != null ? value : defaultValue;
    }

    // for symmetrical reasons...
    public static Object getObject(Map<String, ?> props, String name) {
        return resolvePropertyValue(props, name);
    }

    public static Object resolvePropertyValue(Map<String, ?> props, String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        return (props != null) ? props.get(key) : null;
    }

    /**
     * @param  resolver The {@link PropertyResolver} instance
     * @param  name     The property name
     * @param  value    The new value - if {@code null} or an empty {@link CharSequence} the property is <U>removed</U>
     * @return          The previous value - {@code null} if none
     */
    public static Object updateProperty(PropertyResolver resolver, String name, Object value) {
        return updateProperty(resolver.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String, Object> props, String name, Object value) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        if ((value == null) || ((value instanceof CharSequence) && GenericUtils.isEmpty((CharSequence) value))) {
            return props.remove(key);
        } else {
            return props.put(key, value);
        }
    }

    /**
     * Unwinds the resolvers hierarchy until found one with a non-{@code null} value for the requested property or
     * reached top. If still no value found and the key starts with &quot;org.apache.sshd&quot; then the system
     * properties are also consulted
     *
     * @param  resolver The {@link PropertyResolver} to start from - ignored if {@code null}
     * @param  name     The requested property name
     * @return          The found value or {@code null}
     */
    public static Object resolvePropertyValue(PropertyResolver resolver, String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        for (PropertyResolver r = resolver; r != null; r = r.getParentPropertyResolver()) {
            Map<String, ?> props = r.getProperties();
            Object value = getObject(props, key);
            if (value != null) {
                return value;
            }
        }

        return null;
    }

    /**
     * Unwinds the resolvers hierarchy until found one with a non-{@code null} value for the requested property or
     * reached top.
     *
     * @param  resolver The {@link PropertyResolver} to start from - ignored if {@code null}
     * @param  name     The requested property name
     * @return          The found properties {@link Map} or {@code null}
     */
    public static Map<String, Object> resolvePropertiesSource(PropertyResolver resolver, String name) {
        String key = ValidateUtils.checkNotNullAndNotEmpty(name, "No property name");
        for (PropertyResolver r = resolver; r != null; r = r.getParentPropertyResolver()) {
            Map<String, Object> props = r.getProperties();
            Object value = getObject(props, key);
            if (value != null) {
                return props;
            }
        }

        return null;
    }

    public static PropertyResolver toPropertyResolver(Properties props) {
        if (GenericUtils.isEmpty(props)) {
            return PropertyResolver.EMPTY;
        }

        Collection<String> names = props.stringPropertyNames();
        Map<String, Object> propsMap = new ConcurrentHashMap<>(GenericUtils.size(names));
        for (String key : names) {
            String value = props.getProperty(key);
            if (value == null) {
                continue;
            }
            propsMap.put(key, value);
        }

        return toPropertyResolver(propsMap);
    }

    /**
     * Wraps a {@link Map} into a {@link PropertyResolver} so it can be used with these utilities
     *
     * @param  props The properties map - may be {@code null}/empty if no properties are updated
     * @return       The resolver wrapper
     */
    public static PropertyResolver toPropertyResolver(Map<String, ?> props) {
        return toPropertyResolver(props, null);
    }

    public static PropertyResolver toPropertyResolver(Map<String, ?> props, PropertyResolver parent) {
        return new PropertyResolver() {
            @Override
            public PropertyResolver getParentPropertyResolver() {
                return parent;
            }

            @Override
            @SuppressWarnings({ "unchecked", "rawtypes" })
            public Map<String, Object> getProperties() {
                return (Map) props;
            }

            @Override
            public String toString() {
                return Objects.toString(props);
            }
        };
    }
}
