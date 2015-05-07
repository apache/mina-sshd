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

package org.apache.sshd.common.compression;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;

import org.apache.sshd.common.NamedFactory;
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
                return null;
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
        };
    
    private final String    name;

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final String toString() {
        return getName();
    }

    @Override
    public final boolean isSupported() {
        return true;
    }

    BuiltinCompressions(String n) {
        name = n;
    }

    public static final Set<BuiltinCompressions> VALUES =
            Collections.unmodifiableSet(EnumSet.allOf(BuiltinCompressions.class));
    private static final Map<String,CompressionFactory>   extensions =
            new TreeMap<String,CompressionFactory>(String.CASE_INSENSITIVE_ORDER);

    /**
     * Registered a {@link NamedFactory} to be available besides the built-in
     * ones when parsing configuration
     * @param extension The factory to register
     * @throws IllegalArgumentException if factory instance is {@code null},
     * or overrides a built-in one or overrides another registered factory
     * with the same name (case <U>insensitive</U>).
     */
    public static final void registerExtension(CompressionFactory extension) {
        String  name=ValidateUtils.checkNotNull(extension, "No extension provided", GenericUtils.EMPTY_OBJECT_ARRAY).getName();
        ValidateUtils.checkTrue(fromFactoryName(name) == null, "Extension overrides built-in: %s", name);

        synchronized(extensions) {
            ValidateUtils.checkTrue(!extensions.containsKey(name), "Extension overrides existinh: %s", name);
            extensions.put(name, extension);
        }
    }

    /**
     * @return A {@link SortedSet} of the currently registered extensions, sorted
     * according to the factory name (case <U>insensitive</U>)
     */
    public static final SortedSet<CompressionFactory> getRegisteredExtensions() {
        // TODO for JDK-8 return Collections.emptySortedSet()
        synchronized(extensions) {
            return GenericUtils.asSortedSet(NamedResource.BY_NAME_COMPARATOR, extensions.values());
        }
    }

    /**
     * Unregisters specified extension
     * @param name The factory name - ignored if {@code null}/empty
     * @return The registered extension - {@code null} if not found
     */
    public static final CompressionFactory unregisterExtension(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }
        
        synchronized(extensions) {
            return extensions.remove(name);
        }
    }

    public static final BuiltinCompressions fromFactoryName(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }
        
        for (BuiltinCompressions c : VALUES) {
            if (name.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }
        
        return null;
    }
    /**
     * @param Compressions A comma-separated list of Compressions' names - ignored
     * if {@code null}/empty
     * @return A {@link ParseResult} containing the successfully parsed
     * factories and the unknown ones. <B>Note:</B> it is up to caller to
     * ensure that the lists do not contain duplicates
     */
    public static final ParseResult parseCompressionsList(String Compressions) {
        return parseCompressionsList(GenericUtils.split(Compressions, ','));
    }

    public static final ParseResult parseCompressionsList(String ... Compressions) {
        return parseCompressionsList(GenericUtils.isEmpty((Object[]) Compressions) ? Collections.<String>emptyList() : Arrays.asList(Compressions));
    }

    public static final ParseResult parseCompressionsList(Collection<String> Compressions) {
        if (GenericUtils.isEmpty(Compressions)) {
            return ParseResult.EMPTY;
        }
        
        List<CompressionFactory>    factories=new ArrayList<CompressionFactory>(Compressions.size());
        List<String>                unknown=Collections.<String>emptyList();
        for (String name : Compressions) {
            CompressionFactory  c=resolveFactory(name);
            if (c != null) {
                factories.add(c);
            } else {
                // replace the (unmodifiable) empty list with a real one
                if (unknown.isEmpty()) {
                    unknown = new ArrayList<String>();
                }
                unknown.add(name);
            }
        }
        
        return new ParseResult(factories, unknown);
    }

    /**
     * @param name The factory name
     * @return The factory or {@code null} if it is neither a built-in one
     * or a registered extension 
     */
    public static final CompressionFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        CompressionFactory  c=fromFactoryName(name);
        if (c != null) {
            return c;
        }
        
        synchronized(extensions) {
            return extensions.get(name);
        }
    }

    /**
     * Holds the result of {@link BuiltinCompressions#parseCompressionsList(String)}
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static final class ParseResult extends NamedFactoriesListParseResult<Compression,CompressionFactory> {
        public static final ParseResult EMPTY=new ParseResult(Collections.<CompressionFactory>emptyList(), Collections.<String>emptyList());
        
        public ParseResult(List<CompressionFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }

    public static final class Constants {
        public static final String  NONE="none";
        public static final String  ZLIB="zlib";
        public static final String  DELAYED_ZLIB="zlib@openssh.com";
    }
}
