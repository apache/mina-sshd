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
package org.apache.sshd.server.kex;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.GenericUtils;

/**
 * Helper class to load DH group primes from a file.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class Moduli {
    /**
     * Resource path of internal moduli file
     */
    public static final String INTERNAL_MODULI_RESPATH = "/org/apache/sshd/moduli";

    public static final int MODULI_TYPE_SAFE = 2;
    public static final int MODULI_TESTS_COMPOSITE = 0x01;

    public static class DhGroup {
        private final int size;
        private final BigInteger g;
        private final BigInteger p;

        public DhGroup(int size, BigInteger g, BigInteger p) {
            this.size = size;
            this.g = Objects.requireNonNull(g, "No G value provided");
            this.p = Objects.requireNonNull(p, "No P value provided");
        }

        public int getSize() {
            return size;
        }

        public BigInteger getG() {
            return g;
        }

        public BigInteger getP() {
            return p;
        }

        @Override
        public String toString() {
            return "[size=" + getSize() + ", G=" + getG() + ", P=" + getP() + "]";
        }
    }

    private static final AtomicReference<Map.Entry<String, List<DhGroup>>> INTERNAL_MODULI_HOLDER = new AtomicReference<>();

    // Private constructor
    private Moduli() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static Map.Entry<String, List<DhGroup>> clearInternalModuliCache() {
        return INTERNAL_MODULI_HOLDER.getAndSet(null);
    }

    public static List<DhGroup> loadInternalModuli(URL url) throws IOException {
        if (url == null) {
            throw new FileNotFoundException("No internal moduli resource specified");
        }

        String moduliStr = url.toExternalForm();
        Map.Entry<String, List<DhGroup>> lastModuli = INTERNAL_MODULI_HOLDER.get();
        String lastResource = (lastModuli == null) ? null : lastModuli.getKey();
        if (Objects.equals(lastResource, moduliStr)) {
            return lastModuli.getValue();
        }

        List<DhGroup> groups = parseModuli(url);
        if (GenericUtils.isEmpty(groups)) {
            groups = Collections.emptyList();
        } else {
            groups = Collections.unmodifiableList(groups);
        }

        INTERNAL_MODULI_HOLDER.set(new SimpleImmutableEntry<>(moduliStr, groups));
        return groups;
    }

    public static List<DhGroup> parseModuli(URL url) throws IOException {
        try (InputStream inputStream = url.openStream()) {
            return parseModuli(inputStream);
        }
    }

    public static List<DhGroup> parseModuli(InputStream inputStream) throws IOException {
        try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            return parseModuli(reader);
        }
    }

    public static List<DhGroup> parseModuli(Reader reader) throws IOException {
        if (reader instanceof BufferedReader) {
            return parseModuli((BufferedReader) reader);
        }

        try (BufferedReader r = new BufferedReader(reader)) {
            return parseModuli(r);
        }
    }

    public static List<DhGroup> parseModuli(BufferedReader r) throws IOException {
        List<DhGroup> groups = new ArrayList<>();
        for (String line = r.readLine(); line != null; line = r.readLine()) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;   // skip empty lines
            }

            if (line.charAt(0) == '#') {
                continue;   // skip comments
            }

            String[] parts = line.split("\\s+");
            // Ensure valid line
            if (parts.length != 7) {
                continue;
            }

            // Discard moduli types which are not safe
            int type = Integer.parseInt(parts[1]);
            if (type != MODULI_TYPE_SAFE) {
                continue;
            }

            // Discard untested moduli
            int tests = Integer.parseInt(parts[2]);
            if (((tests & MODULI_TESTS_COMPOSITE) != 0) || ((tests & ~MODULI_TESTS_COMPOSITE) == 0)) {
                continue;
            }

            // Discard untried
            int tries = Integer.parseInt(parts[3]);
            if (tries == 0) {
                continue;
            }

            DhGroup group = new DhGroup(
                    Integer.parseInt(parts[4]) + 1,
                    new BigInteger(parts[5], 16),
                    new BigInteger(parts[6], 16));
            groups.add(group);
        }

        return groups;
    }
}
