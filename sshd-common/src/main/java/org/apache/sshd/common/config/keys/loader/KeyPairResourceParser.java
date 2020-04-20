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

package org.apache.sshd.common.config.keys.loader;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyPairResourceParser extends KeyPairResourceLoader {
    /**
     * An empty parser that never fails, but always report that it cannot extract key pairs and returns empty list if
     * asked to load
     */
    KeyPairResourceParser EMPTY = new KeyPairResourceParser() {
        @Override
        public Collection<KeyPair> loadKeyPairs(
                SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider, List<String> lines)
                throws IOException, GeneralSecurityException {
            return Collections.emptyList();
        }

        @Override
        public boolean canExtractKeyPairs(NamedResource resourceKey, List<String> lines)
                throws IOException, GeneralSecurityException {
            return false;
        }

        @Override
        public String toString() {
            return "EMPTY";
        }
    };

    /**
     * @param  resourceKey              A hint as to the origin of the text lines
     * @param  lines                    The resource lines
     * @return                          {@code true} if the parser can extract some key pairs from the lines
     * @throws IOException              If failed to process the lines
     * @throws GeneralSecurityException If failed to extract information regarding the possibility to extract the key
     *                                  pairs
     */
    boolean canExtractKeyPairs(NamedResource resourceKey, List<String> lines)
            throws IOException, GeneralSecurityException;

    /**
     * Converts the lines assumed to contain BASE-64 encoded data into the actual content bytes.
     *
     * @param  lines The data lines - empty lines and spaces are automatically deleted <U>before</U> BASE-64 decoding
     *               takes place.
     * @return       The decoded data bytes
     * @see          #joinDataLines(Collection)
     */
    static byte[] extractDataBytes(Collection<String> lines) {
        String data = joinDataLines(lines);
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(data);
    }

    static String joinDataLines(Collection<String> lines) {
        String data = GenericUtils.join(lines, ' ');
        data = data.replaceAll("\\s", "");
        data = data.trim();
        return data;
    }

    static boolean containsMarkerLine(List<String> lines, String marker) {
        return containsMarkerLine(
                lines, Collections.singletonList(ValidateUtils.checkNotNullAndNotEmpty(marker, "No marker")));
    }

    static boolean containsMarkerLine(List<String> lines, List<String> markers) {
        return findMarkerLine(lines, markers) != null;
    }

    /**
     * Attempts to locate a line that contains one of the markers
     *
     * @param  lines   The list of lines to scan - ignored if {@code null}/empty
     * @param  markers The markers to match - ignored if {@code null}/empty
     * @return         A {@link SimpleImmutableEntry} whose key is the <U>first</U> line index that matched and value
     *                 the matched marker index - {@code null} if no match found
     * @see            #findMarkerLine(List, int, List)
     */
    static SimpleImmutableEntry<Integer, Integer> findMarkerLine(List<String> lines, List<String> markers) {
        return findMarkerLine(lines, 0, markers);
    }

    /**
     * Attempts to locate a line that contains one of the markers
     *
     * @param  lines     The list of lines to scan - ignored if {@code null}/empty
     * @param  startLine The scan start line index
     * @param  markers   The markers to match - ignored if {@code null}/empty
     * @return           A {@link SimpleImmutableEntry} whose key is the <U>first</U> line index that matched and value
     *                   the matched marker index - {@code null} if no match found
     */
    static SimpleImmutableEntry<Integer, Integer> findMarkerLine(List<String> lines, int startLine, List<String> markers) {
        if (GenericUtils.isEmpty(lines) || GenericUtils.isEmpty(markers)) {
            return null;
        }

        for (int lineIndex = startLine; lineIndex < lines.size(); lineIndex++) {
            String l = lines.get(lineIndex);
            for (int markerIndex = 0; markerIndex < markers.size(); markerIndex++) {
                String m = markers.get(markerIndex);
                if (l.contains(m)) {
                    return new SimpleImmutableEntry<>(lineIndex, markerIndex);
                }
            }
        }

        return null;
    }

    static KeyPairResourceParser aggregate(KeyPairResourceParser... parsers) {
        return aggregate(Arrays.asList(ValidateUtils.checkNotNullAndNotEmpty(parsers, "No parsers to aggregate")));
    }

    static KeyPairResourceParser aggregate(Collection<? extends KeyPairResourceParser> parsers) {
        ValidateUtils.checkNotNullAndNotEmpty(parsers, "No parsers to aggregate");
        return new KeyPairResourceParser() {
            @Override
            public Collection<KeyPair> loadKeyPairs(
                    SessionContext session, NamedResource resourceKey, FilePasswordProvider passwordProvider,
                    List<String> lines)
                    throws IOException, GeneralSecurityException {
                Collection<KeyPair> keyPairs = Collections.emptyList();
                for (KeyPairResourceParser p : parsers) {
                    if (!p.canExtractKeyPairs(resourceKey, lines)) {
                        continue;
                    }

                    Collection<KeyPair> kps = p.loadKeyPairs(session, resourceKey, passwordProvider, lines);
                    if (GenericUtils.isEmpty(kps)) {
                        continue;
                    }

                    if (GenericUtils.isEmpty(keyPairs)) {
                        keyPairs = new LinkedList<>(kps);
                    } else {
                        keyPairs.addAll(kps);
                    }
                }

                return keyPairs;
            }

            @Override
            public boolean canExtractKeyPairs(NamedResource resourceKey, List<String> lines)
                    throws IOException, GeneralSecurityException {
                for (KeyPairResourceParser p : parsers) {
                    if (p.canExtractKeyPairs(resourceKey, lines)) {
                        return true;
                    }
                }

                return false;
            }

            @Override
            public String toString() {
                return KeyPairResourceParser.class.getSimpleName() + "[aggregate]";
            }
        };
    }
}
