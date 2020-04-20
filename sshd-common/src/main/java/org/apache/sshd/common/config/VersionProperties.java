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

package org.apache.sshd.common.config;

import java.io.InputStream;
import java.util.Collections;
import java.util.Iterator;
import java.util.NavigableMap;
import java.util.Properties;
import java.util.TreeMap;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class VersionProperties {
    /**
     * Property used to hold the reported version
     */
    public static final String REPORTED_VERSION = "sshd-version";

    private static final class LazyVersionPropertiesHolder {
        private static final NavigableMap<String, String> PROPERTIES = Collections.unmodifiableNavigableMap(
                loadVersionProperties(LazyVersionPropertiesHolder.class));

        private LazyVersionPropertiesHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        private static NavigableMap<String, String> loadVersionProperties(Class<?> anchor) {
            return loadVersionProperties(anchor, ThreadUtils.iterateDefaultClassLoaders(anchor));
        }

        private static NavigableMap<String, String> loadVersionProperties(
                Class<?> anchor, Iterator<? extends ClassLoader> loaders) {
            while ((loaders != null) && loaders.hasNext()) {
                ClassLoader cl = loaders.next();
                Properties props;
                try (InputStream input = cl.getResourceAsStream("org/apache/sshd/sshd-version.properties")) {
                    if (input == null) {
                        continue;
                    }

                    props = new Properties();
                    props.load(input);
                } catch (Exception e) {
                    Logger log = LoggerFactory.getLogger(anchor);
                    log.warn("Failed ({}) to load version properties from {}: {}",
                            e.getClass().getSimpleName(), cl, e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("Version property failure details for loader=" + cl, e);
                    }
                    continue;
                }

                NavigableMap<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                for (String key : props.stringPropertyNames()) {
                    String propValue = props.getProperty(key);
                    String value = GenericUtils.trimToEmpty(propValue);
                    if (GenericUtils.isEmpty(value)) {
                        continue; // we have no need for empty values
                    }

                    String prev = result.put(key, value);
                    if (prev != null) {
                        Logger log = LoggerFactory.getLogger(anchor);
                        log.warn("Multiple values for key=" + key + ": current=" + value + ", previous=" + prev);
                    }
                }

                return result;
            }

            return Collections.emptyNavigableMap();
        }
    }

    private VersionProperties() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @return A case <u>insensitive</u> un-modifiable {@link NavigableMap} of the {@code sshd-version.properties} data
     */
    @SuppressWarnings("synthetic-access")
    public static NavigableMap<String, String> getVersionProperties() {
        return LazyVersionPropertiesHolder.PROPERTIES;
    }
}
