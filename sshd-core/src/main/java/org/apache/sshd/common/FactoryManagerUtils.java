/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common;

import java.util.Map;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FactoryManagerUtils {
    /**
     * @param session      The {@link Session} instance
     * @param name         The property name
     * @param defaultValue The default value to return if the specified property
     *                     does not exist in the properties map
     * @return The resolved property
     * @throws NumberFormatException if malformed value
     */
    public static long getLongProperty(Session session, String name, long defaultValue) {
        return getLongProperty(session.getFactoryManager(), name, defaultValue);
    }

    /**
     * @param manager      The {@link FactoryManager} instance
     * @param name         The property name
     * @param defaultValue The default value to return if the specified property
     *                     does not exist in the properties map
     * @return The resolved property
     * @throws NumberFormatException if malformed value
     */
    public static long getLongProperty(FactoryManager manager, String name, long defaultValue) {
        return getLongProperty(manager.getProperties(), name, defaultValue);
    }

    /**
     * @param props        The properties {@link Map} - ignored if {@code null}/empty
     * @param name         The property name
     * @param defaultValue The default value to return if the specified property
     *                     does not exist in the properties map or is an empty string
     * @return The resolved property
     * @throws NumberFormatException if malformed value
     */
    public static long getLongProperty(Map<String,?> props, String name, long defaultValue) {
        Object value = GenericUtils.isEmpty(props) ? null : props.get(name);
        if (value == null) {
            return defaultValue;
        } else if (value instanceof Long) {
            return (Long) value;
        } else {    // we parse the string in case it is not a valid long value
            return Long.parseLong(value.toString());
        }
    }

    /**
     * @param session The {@link Session} instance
     * @param name    The property name
     * @return The {@link Long} value or {@code null} if property not found or empty string
     * @throws NumberFormatException if malformed value
     */
    public static Long getLong(Session session, String name) {
        return getLong(session.getFactoryManager(), name);
    }

    /**
     * @param manager The {@link FactoryManager} instance
     * @param name    The property name
     * @return The {@link Long} value or {@code null} if property not found
     * @throws NumberFormatException if malformed value
     */
    public static Long getLong(FactoryManager manager, String name) {
        return getLong(manager.getProperties(), name);
    }

    /**
     * @param props The properties {@link Map} - ignored if {@code null}/empty
     * @param name  The property name
     * @return The {@link Long} value or {@code null} if property not found or
     * empty string
     * @throws NumberFormatException if malformed value
     */
    public static Long getLong(Map<String,?> props, String name) {
        Object value = GenericUtils.isEmpty(props) ? null : props.get(name);
        if (value == null) {
            return null;
        } else if (value instanceof Long) {
            return (Long) value;
        } else {    // we parse the string in case it is not a valid long value
            return Long.valueOf(value.toString());
        }
    }

    public static Object updateProperty(Session session, String name, long value) {
        return updateProperty(session, name, Long.toString(value));
    }

    public static Object updateProperty(FactoryManager manager, String name, long value) {
        return updateProperty(manager.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String,Object> props, String name, long value) {
        return updateProperty(props, name, Long.valueOf(value));
    }

    public static int getIntProperty(Session session, String name, int defaultValue) {
        return getIntProperty(session.getFactoryManager(), name, defaultValue);
    }

    public static int getIntProperty(FactoryManager manager, String name, int defaultValue) {
        return getIntProperty(manager.getProperties(), name, defaultValue);
    }

    public static int getIntProperty(Map<String,?> props, String name, int defaultValue) {
        Object value = GenericUtils.isEmpty(props) ? null : props.get(name);
        if (value == null) {
            return defaultValue;
        } else if (value instanceof Integer) {
            return (Integer) value;
        } else {    // we parse the string in case this is NOT an integer
            return Integer.parseInt(value.toString());
        }
    }

    public static Integer getInteger(Session session, String name) {
        return getInteger(session.getFactoryManager(), name);
    }

    public static Integer getInteger(FactoryManager manager, String name) {
        return getInteger(manager.getProperties(), name);
    }

    public static Integer getInteger(Map<String,?> props, String name) {
        Object value = GenericUtils.isEmpty(props) ? null : props.get(name);
        if (value == null) {
            return null;
        } else if (value instanceof Integer) {
            return (Integer) value;
        } else {    // we parse the string in case this is NOT an integer
            return Integer.valueOf(value.toString());
        }
    }

    public static Object updateProperty(Session session, String name, int value) {
        return updateProperty(session.getFactoryManager(), name, value);
    }

    public static Object updateProperty(FactoryManager manager, String name, int value) {
        return updateProperty(manager.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String,Object> props, String name, int value) {
        return updateProperty(props, name, Integer.valueOf(value));
    }

    public static boolean getBooleanProperty(Session session, String name, boolean defaultValue) {
        return getBooleanProperty(session.getFactoryManager(), name, defaultValue);
    }

    public static boolean getBooleanProperty(FactoryManager manager, String name, boolean defaultValue) {
        return getBooleanProperty(manager.getProperties(), name, defaultValue);
    }

    public static boolean getBooleanProperty(Map<String,?> props, String name, boolean defaultValue) {
        Boolean value = getBoolean(props, name);
        if (value == null) {
            return defaultValue;
        } else {
            return value;
        }
    }

    public static Boolean getBoolean(Session session, String name) {
        return getBoolean(session.getFactoryManager(), name);
    }

    public static Boolean getBoolean(FactoryManager manager, String name) {
        return getBoolean(manager.getProperties(), name);
    }

    public static Boolean getBoolean(Map<String,?> props, String name) {
        Object  value = GenericUtils.isEmpty(props) ? null : props.get(name);
        if (value == null) {
            return null;
        } else if (value instanceof Boolean) {
            return (Boolean) value;
        } else {
            return Boolean.valueOf(value.toString());
        }
    }

    public static Object updateProperty(Session session, String name, boolean value) {
        return updateProperty(session.getFactoryManager(), name, value);
    }

    public static Object updateProperty(FactoryManager manager, String name, boolean value) {
        return updateProperty(manager.getProperties(), name, value);
    }

    public static Object updateProperty(Map<String,Object> props, String name, boolean value) {
        return updateProperty(props, name, Boolean.valueOf(value));
    }

    public static String getString(Session session, String name) {
        return getStringProperty(session, name, null);
    }

    public static String getStringProperty(Session session, String name, String defaultValue) {
        return getStringProperty(session.getFactoryManager(), name, defaultValue);
    }

    public static String getString(FactoryManager manager, String name) {
        return getStringProperty(manager, name, null);
    }

    public static String getStringProperty(FactoryManager manager, String name, String defaultValue) {
        return getStringProperty(manager.getProperties(), name, defaultValue);
    }

    public static String getString(Map<String,?> props, String name) {
        return getStringProperty(props, name, null);
    }

    public static String getStringProperty(Map<String,?> props, String name, String defaultValue) {
        Object value = GenericUtils.isEmpty(props) ? null : props.get(name);
        String s = (value == null) ? null : value.toString();
        if (GenericUtils.isEmpty(s)) {
            return defaultValue;
        } else {
            return s;
        }
    }

    public static Object updateProperty(Session session, String name, Object value) {
        return updateProperty(session.getFactoryManager(), name, value);
    }

    public static Object updateProperty(FactoryManager manager, String name, Object value) {
        return updateProperty(manager.getProperties(), name, value);
    }

    /**
     * @param props The {@link Map} of properties to update
     * @param name  The property name
     * @param value The property value - if {@code null}/empty then the
     * specified property is <U>removed</U> from the properties map
     * @return The removed or previous value (if any)
     */
    public static Object updateProperty(Map<String,Object> props, String name, Object value) {
        if ((value == null) || ((value instanceof CharSequence) && GenericUtils.isEmpty((CharSequence) value))) {
            return props.remove(name);
        } else {
            return props.put(name, value);
        }
    }
}
