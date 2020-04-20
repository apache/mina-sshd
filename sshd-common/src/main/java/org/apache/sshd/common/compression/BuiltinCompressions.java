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

package org.apache.sshd.common.compression;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.NamedFactoriesListParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinCompressions implements CompressionFactory {
    none(Constants.NONE) {
        @Override
        public Compression create() {
            return new CompressionNone();
        }

        @Override
        public boolean isCompressionExecuted() {
            return false;
        }
    },
    zlib(Constants.ZLIB) {
        @Override
        public Compression create() {
            return new CompressionZlib();
        }
    },
    delayedZlib(Constants.DELAYED_ZLIB) {
        @Override
        public Compression create() {
            return new CompressionDelayedZlib();
        }

        @Override
        public boolean isDelayed() {
            return true;
        }
    };

    public static final Set<BuiltinCompressions> VALUES = Collections.unmodifiableSet(EnumSet.allOf(BuiltinCompressions.class));

    private static final Map<String, CompressionFactory> EXTENSIONS = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    private final String name;

    BuiltinCompressions(String n) {
        name = n;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public boolean isDelayed() {
        return false;
    }

    @Override
    public boolean isCompressionExecuted() {
        return true;
    }

    @Override
    public final String toString() {
        return getName();
    }

    @Override
    public final boolean isSupported() {
        return true;
    }

    /**
     * Registered a {@link org.apache.sshd.common.NamedFactory} to be available besides the built-in ones when parsing
     * configuration
     *
     * @param  extension                The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null}, or overrides a built-in one or overrides
     *                                  another registered factory with the same name (case <U>insensitive</U>).
     */
    public static void registerExtension(CompressionFactory extension) {
        String name = Objects.requireNonNull(extension, "No extension provided").getName();
        ValidateUtils.checkTrue(fromFactoryName(name) == null, "Extension overrides built-in: %s", name);

        synchronized (EXTENSIONS) {
            ValidateUtils.checkTrue(!EXTENSIONS.containsKey(name), "Extension overrides existing: %s", name);
            EXTENSIONS.put(name, extension);
        }
    }

    /**
     * @return A {@link SortedSet} of the currently registered extensions, sorted according to the factory name (case
     *         <U>insensitive</U>)
     */
    public static NavigableSet<CompressionFactory> getRegisteredExtensions() {
        synchronized (EXTENSIONS) {
            return GenericUtils.asSortedSet(NamedResource.BY_NAME_COMPARATOR, EXTENSIONS.values());
        }
    }

    /**
     * Unregisters specified extension
     *
     * @param  name The factory name - ignored if {@code null}/empty
     * @return      The registered extension - {@code null} if not found
     */
    public static CompressionFactory unregisterExtension(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.remove(name);
        }
    }

    public static BuiltinCompressions fromFactoryName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }

    /**
     * @param  compressions A comma-separated list of Compressions' names - ignored if {@code null}/empty
     * @return              A {@link ParseResult} containing the successfully parsed factories and the unknown ones.
     *                      <B>Note:</B> it is up to caller to ensure that the lists do not contain duplicates
     */
    public static ParseResult parseCompressionsList(String compressions) {
        return parseCompressionsList(GenericUtils.split(compressions, ','));
    }

    public static ParseResult parseCompressionsList(String... compressions) {
        return parseCompressionsList(
                GenericUtils.isEmpty((Object[]) compressions) ? Collections.emptyList() : Arrays.asList(compressions));
    }

    public static ParseResult parseCompressionsList(Collection<String> compressions) {
        if (GenericUtils.isEmpty(compressions)) {
            return ParseResult.EMPTY;
        }

        List<CompressionFactory> factories = new ArrayList<>(compressions.size());
        List<String> unknown = Collections.emptyList();
        for (String name : compressions) {
            CompressionFactory c = resolveFactory(name);
            if (c != null) {
                factories.add(c);
            } else {
                // replace the (unmodifiable) empty list with a real one
                if (unknown.isEmpty()) {
                    unknown = new ArrayList<>();
                }
                unknown.add(name);
            }
        }

        return new ParseResult(factories, unknown);
    }

    /**
     * @param  name The factory name
     * @return      The factory or {@code null} if it is neither a built-in one or a registered extension
     */
    public static CompressionFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        CompressionFactory c = fromFactoryName(name);
        if (c != null) {
            return c;
        }

        synchronized (EXTENSIONS) {
            return EXTENSIONS.get(name);
        }
    }

    /**
     * Holds the result of {@link BuiltinCompressions#parseCompressionsList(String)}
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class ParseResult extends NamedFactoriesListParseResult<Compression, CompressionFactory> {
        public static final ParseResult EMPTY = new ParseResult(Collections.emptyList(), Collections.emptyList());

        public ParseResult(List<CompressionFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }

    public static final class Constants {
        public static final String NONE = "none";
        public static final String ZLIB = "zlib";
        public static final String DELAYED_ZLIB = "zlib@openssh.com";

        private Constants() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }
}
