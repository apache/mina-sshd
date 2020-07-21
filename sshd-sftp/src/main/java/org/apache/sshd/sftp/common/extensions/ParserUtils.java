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

package org.apache.sshd.sftp.common.extensions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.sftp.common.extensions.Supported2Parser.Supported2;
import org.apache.sshd.sftp.common.extensions.SupportedParser.Supported;
import org.apache.sshd.sftp.common.extensions.openssh.FstatVfsExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.FsyncExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.HardLinkExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.LSetStatExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.PosixRenameExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.StatVfsExtensionParser;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH - section 3.4</A>
 */
public final class ParserUtils {
    public static final Collection<ExtensionParser<?>> BUILT_IN_PARSERS = Collections.unmodifiableList(
            Arrays.<ExtensionParser<?>> asList(
                    VendorIdParser.INSTANCE,
                    NewlineParser.INSTANCE,
                    VersionsParser.INSTANCE,
                    SupportedParser.INSTANCE,
                    Supported2Parser.INSTANCE,
                    AclSupportedParser.INSTANCE,
                    // OpenSSH extensions
                    PosixRenameExtensionParser.INSTANCE,
                    StatVfsExtensionParser.INSTANCE,
                    FstatVfsExtensionParser.INSTANCE,
                    HardLinkExtensionParser.INSTANCE,
                    FsyncExtensionParser.INSTANCE,
                    LSetStatExtensionParser.INSTANCE));

    private static final NavigableMap<String, ExtensionParser<?>> PARSERS_MAP = Collections.unmodifiableNavigableMap(
            BUILT_IN_PARSERS.stream()
                    .collect(Collectors.toMap(
                            NamedResource::getName, Function.identity(),
                            GenericUtils.throwingMerger(), () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER))));

    private ParserUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param  parser The {@link ExtensionParser} to register
     * @return        The replaced parser (by name) - {@code null} if no previous parser for this extension name
     */
    public static ExtensionParser<?> registerParser(ExtensionParser<?> parser) {
        Objects.requireNonNull(parser, "No parser instance");

        synchronized (PARSERS_MAP) {
            return PARSERS_MAP.put(parser.getName(), parser);
        }
    }

    /**
     * @param  name The extension name - ignored if {@code null}/empty
     * @return      The removed {@link ExtensionParser} - {@code null} if none registered for this extension name
     */
    public static ExtensionParser<?> unregisterParser(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (PARSERS_MAP) {
            return PARSERS_MAP.remove(name);
        }
    }

    /**
     * @param  name The extension name - ignored if {@code null}/empty
     * @return      The registered {@link ExtensionParser} - {@code null} if none registered for this extension name
     */
    public static ExtensionParser<?> getRegisteredParser(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized (PARSERS_MAP) {
            return PARSERS_MAP.get(name);
        }
    }

    public static Set<String> getRegisteredParsersNames() {
        synchronized (PARSERS_MAP) {
            if (PARSERS_MAP.isEmpty()) {
                return Collections.emptySet();
            } else { // return a copy in order to avoid concurrent modification issues
                return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, PARSERS_MAP.keySet());
            }
        }
    }

    public static List<ExtensionParser<?>> getRegisteredParsers() {
        synchronized (PARSERS_MAP) {
            if (PARSERS_MAP.isEmpty()) {
                return Collections.emptyList();
            } else { // return a copy in order to avoid concurrent modification issues
                return new ArrayList<>(PARSERS_MAP.values());
            }
        }
    }

    public static Set<String> supportedExtensions(Map<String, ?> parsed) {
        if (GenericUtils.isEmpty(parsed)) {
            return Collections.emptySet();
        }

        Supported sup = (Supported) parsed.get(SupportedParser.INSTANCE.getName());
        Collection<String> extra = (sup == null) ? null : sup.extensionNames;
        Supported2 sup2 = (Supported2) parsed.get(Supported2Parser.INSTANCE.getName());
        Collection<String> extra2 = (sup2 == null) ? null : sup2.extensionNames;
        if (GenericUtils.isEmpty(extra)) {
            return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, extra2);
        } else if (GenericUtils.isEmpty(extra2)) {
            return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, extra);
        }

        Set<String> result = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        result.addAll(extra);
        result.addAll(extra2);
        return result;
    }

    /**
     * @param  extensions The received extensions in encoded form
     * @return            A {@link Map} of all the successfully decoded extensions where key=extension name (same as in
     *                    the original map), value=the decoded extension value. Extensions for which there is no
     *                    registered parser are <U>ignored</U>
     * @see               #getRegisteredParser(String)
     * @see               ExtensionParser#parse(byte[])
     */
    public static Map<String, Object> parse(Map<String, byte[]> extensions) {
        if (GenericUtils.isEmpty(extensions)) {
            return Collections.emptyMap();
        }

        Map<String, Object> data = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        extensions.forEach((name, value) -> {
            Object result = parse(name, value);
            if (result == null) {
                return;
            }
            data.put(name, result);
        });

        return data;
    }

    public static Object parse(String name, byte... encoded) {
        ExtensionParser<?> parser = getRegisteredParser(name);
        if (parser == null) {
            return null;
        } else {
            return parser.parse(encoded);
        }
    }
}
