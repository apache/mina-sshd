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

import java.util.Collections;
import java.util.Map;

/**
 * Indicates an entity that can be configured using properties. The properties
 * are simple name-value pairs where the actual value type depends on the
 * property. Some automatic conversions may be available - e.g., from a string
 * to a numeric or {@code boolean} value, or from {@code int} to {@code long},
 * etc.. <B>Note:</B> implementations may decide to use case <U>insensitive</U>
 * property names, therefore it is <U><B>highly discouraged</B></U> to use names
 * that differ from each other only in case sensitivity. Also, implementations
 * may choose to trim whitespaces, thus such are also highly discouraged.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface PropertyResolver {
    /**
     * An &quot;empty&quot; resolver with no properties and no parent
     */
    PropertyResolver EMPTY = new PropertyResolver() {
        @Override
        public PropertyResolver getParentPropertyResolver() {
            return null;
        }

        @Override
        public Map<String, Object> getProperties() {
            return Collections.emptyMap();
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @return The parent resolver that can be used to query for missing
     *         properties - {@code null} if no parent
     */
    PropertyResolver getParentPropertyResolver();

    /**
     * <P>
     * A map of properties that can be used to configure the SSH server or
     * client. This map will never be changed by either the server or client and
     * is not supposed to be changed at runtime (changes are not bound to have
     * any effect on a running client or server), though it may affect the
     * creation of sessions later as these values are usually not cached.
     * </P>
     *
     * <P>
     * <B>Note:</B> the <U>type</U> of the mapped property should match the
     * expected configuration value type - {@code Long, Integer, Boolean,
     * String}, etc.... If it doesn't, the {@code toString()} result of the
     * mapped value is used to convert it to the required type. E.g., if the
     * mapped value is the <U>string</U> &quot;1234&quot; and the expected value
     * is a {@code long} then it will be parsed into one. Also, if the mapped
     * value is an {@code Integer} but a {@code long} is expected, then it will
     * be converted into one.
     * </P>
     *
     * @return a valid <code>Map</code> containing configuration values, never
     *         {@code null}
     */
    Map<String, Object> getProperties();
}
