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

package org.apache.sshd.common.kex.extension;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.kex.extension.parser.DelayCompression;
import org.apache.sshd.common.kex.extension.parser.Elevation;
import org.apache.sshd.common.kex.extension.parser.NoFlowControl;
import org.apache.sshd.common.kex.extension.parser.ServerSignatureAlgorithms;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Provides some helpers for <A HREF="https://tools.ietf.org/html/rfc8308">RFC 8308</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class KexExtensions {
    public static final byte SSH_MSG_EXT_INFO = 7;
    public static final byte SSH_MSG_NEWCOMPRESS = 8;

    public static final String CLIENT_KEX_EXTENSION = "ext-info-c";
    public static final String SERVER_KEX_EXTENSION = "ext-info-s";

    @SuppressWarnings("checkstyle:Indentation")
    public static final Predicate<String> IS_KEX_EXTENSION_SIGNAL
            = n -> CLIENT_KEX_EXTENSION.equalsIgnoreCase(n) || SERVER_KEX_EXTENSION.equalsIgnoreCase(n);

    /**
     * A case <U>insensitive</U> map of all the default known {@link KexExtensionParser} where key=the extension name
     */
    private static final NavigableMap<String, KexExtensionParser<?>> EXTENSION_PARSERS = Stream.of(
            ServerSignatureAlgorithms.INSTANCE,
            NoFlowControl.INSTANCE,
            Elevation.INSTANCE,
            DelayCompression.INSTANCE)
            .collect(Collectors.toMap(
                    NamedResource::getName, Function.identity(),
                    GenericUtils.throwingMerger(), () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));

    private KexExtensions() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * @return A case <U>insensitive</U> copy of the currently registered {@link KexExtensionParser}s names
     */
    public static NavigableSet<String> getRegisteredExtensionParserNames() {
        synchronized (EXTENSION_PARSERS) {
            return EXTENSION_PARSERS.isEmpty()
                    ? Collections.emptyNavigableSet()
                    : GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, EXTENSION_PARSERS.keySet());
        }
    }

    /**
     * @param  name The (never {@code null}/empty) extension name
     * @return      The registered {@code KexExtensionParser} for the (case <U>insensitive</U>) extension name -
     *              {@code null} if no match found
     */
    public static KexExtensionParser<?> getRegisteredExtensionParser(String name) {
        ValidateUtils.checkNotNullAndNotEmpty(name, "No extension name provided");
        synchronized (EXTENSION_PARSERS) {
            return EXTENSION_PARSERS.get(name);
        }
    }

    /**
     * Registers a {@link KexExtensionParser} for a named extension
     *
     * @param  parser The (never {@code null}) parser to register
     * @return        The replaced parser for the named extension (case <U>insensitive</U>) - {@code null} if no
     *                previous parser registered for this extension
     */
    public static KexExtensionParser<?> registerExtensionParser(KexExtensionParser<?> parser) {
        Objects.requireNonNull(parser, "No parser provided");
        String name = ValidateUtils.checkNotNullAndNotEmpty(parser.getName(), "No extension name provided");
        synchronized (EXTENSION_PARSERS) {
            return EXTENSION_PARSERS.put(name, parser);
        }
    }

    /**
     * Registers {@link KexExtensionParser} for a named extension
     *
     * @param  name The (never {@code null}/empty) extension name
     * @return      The removed {@code KexExtensionParser} for the (case <U>insensitive</U>) extension name -
     *              {@code null} if no match found
     */
    public static KexExtensionParser<?> unregisterExtensionParser(String name) {
        ValidateUtils.checkNotNullAndNotEmpty(name, "No extension name provided");
        synchronized (EXTENSION_PARSERS) {
            return EXTENSION_PARSERS.remove(name);
        }
    }

    /**
     * Attempts to parse an {@code SSH_MSG_EXT_INFO} message
     *
     * @param  buffer      The {@link Buffer} containing the message
     * @return             A {@link List} of key/value &quot;pairs&quot; where key=the extension name, value=the parsed
     *                     value using the matching registered {@link KexExtensionParser}. If no such parser found then
     *                     the raw value bytes are set as the extension value.
     * @throws IOException If failed to parse one of the extensions
     * @see                <A HREF="https://tools.ietf.org/html/rfc8308#section-2.3">RFC-8308 - section 2.3</A>
     */
    public static List<Map.Entry<String, ?>> parseExtensions(Buffer buffer) throws IOException {
        int count = buffer.getInt();
        if (count == 0) {
            return Collections.emptyList();
        }

        List<Map.Entry<String, ?>> entries = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            String name = buffer.getString();
            byte[] data = buffer.getBytes();
            KexExtensionParser<?> parser = getRegisteredExtensionParser(name);
            Object value = (parser == null) ? data : parser.parseExtension(data);
            entries.add(new SimpleImmutableEntry<>(name, value));
        }

        return entries;
    }

    /**
     * Creates an {@code SSH_MSG_EXT_INFO} message using the provided extensions.
     *
     * @param  exts        A {@link Collection} of key/value &quot;pairs&quot; where key=the extension name, value=the
     *                     extension value. <B>Note:</B> if a registered {@link KexExtensionParser} exists for the name,
     *                     then it is assumed that the value is of the correct type. If no registered parser found the
     *                     value is assumed to be either the encoded value as an array of bytes or as another
     *                     {@link Readable} (e.g., another {@link Buffer}) or a {@link ByteBuffer}.
     * @param  buffer      The target {@link Buffer} - assumed to already contain the {@code SSH_MSG_EXT_INFO} opcode
     * @throws IOException If failed to encode
     */
    public static void putExtensions(Collection<? extends Map.Entry<String, ?>> exts, Buffer buffer) throws IOException {
        int count = GenericUtils.size(exts);
        buffer.putInt(count);
        if (count <= 0) {
            return;
        }

        for (Map.Entry<String, ?> ee : exts) {
            String name = ee.getKey();
            Object value = ee.getValue();
            @SuppressWarnings("unchecked")
            KexExtensionParser<Object> parser = (KexExtensionParser<Object>) getRegisteredExtensionParser(name);
            if (parser != null) {
                parser.putExtension(value, buffer);
            } else {
                buffer.putOptionalBufferedData(value);
            }
        }
    }
}
