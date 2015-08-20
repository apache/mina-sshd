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

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
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
    private static class LazyHolder {
        private static final Map<String, String> PROPERTIES =
                Collections.unmodifiableMap(loadVersionProperties(LazyHolder.class));

        private static Map<String, String> loadVersionProperties(Class<?> anchor) {
            return loadVersionProperties(anchor, ThreadUtils.resolveDefaultClassLoader(anchor));
        }

        private static Map<String, String> loadVersionProperties(Class<?> anchor, ClassLoader loader) {
            Map<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            try {
                InputStream input = loader.getResourceAsStream("org/apache/sshd/sshd-version.properties");
                if (input == null) {
                    throw new FileNotFoundException("Resource does not exists");
                }

                Properties props = new Properties();
                try {
                    props.load(input);
                } finally {
                    input.close();
                }

                for (String key : props.stringPropertyNames()) {
                    String value = GenericUtils.trimToEmpty(props.getProperty(key));
                    if (GenericUtils.isEmpty(value)) {
                        continue;   // we have no need for empty value
                    }

                    String prev = result.put(key, value);
                    if (prev != null) {
                        Logger log = LoggerFactory.getLogger(anchor);
                        log.warn("Multiple values for key=" + key + ": current=" + value + ", previous=" + prev);
                    }
                }
            } catch (Exception e) {
                Logger log = LoggerFactory.getLogger(anchor);
                log.warn("Failed (" + e.getClass().getSimpleName() + ") to load version properties: " + e.getMessage());
            }

            return result;
        }
    }

    private VersionProperties() {
        throw new UnsupportedOperationException("No instance");
    }

    @SuppressWarnings("synthetic-access")
    public static Map<String, String> getVersionProperties() {
        return LazyHolder.PROPERTIES;
    }

}
