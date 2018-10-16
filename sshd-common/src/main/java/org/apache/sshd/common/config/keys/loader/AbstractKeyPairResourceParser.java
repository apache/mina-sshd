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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractKeyPairResourceParser extends AbstractLoggingBean implements KeyPairResourceParser {
    private final List<String> beginners;
    private final List<String> enders;
    private final List<List<String>> endingMarkers;

    /**
     * @param beginners The markers that indicate the beginning of a parsing block
     * @param enders The <U>matching</U> (by position) markers that indicate the end of a parsing block
     */
    protected AbstractKeyPairResourceParser(List<String> beginners, List<String> enders) {
        this.beginners = ValidateUtils.checkNotNullAndNotEmpty(beginners, "No begin markers");
        this.enders = ValidateUtils.checkNotNullAndNotEmpty(enders, "No end markers");
        ValidateUtils.checkTrue(
                beginners.size() == enders.size(), "Mismatched begin(%d)/end(%d) markers sizes", beginners.size(), enders.size());
        endingMarkers = new ArrayList<>(enders.size());
        enders.forEach(m -> endingMarkers.add(Collections.singletonList(m)));
    }

    public List<String> getBeginners() {
        return beginners;
    }

    public List<String> getEnders() {
        return enders;
    }

    /**
     * @return A {@link List} of same size as the ending markers, where
     * each ending marker is encapsulated inside a singleton list and
     * resides as the <U>same index</U> as the marker it encapsulates
     */
    public List<List<String>> getEndingMarkers() {
        return endingMarkers;
    }

    @Override
    public boolean canExtractKeyPairs(String resourceKey, List<String> lines) throws IOException, GeneralSecurityException {
        return KeyPairResourceParser.containsMarkerLine(lines, getBeginners());
    }

    @Override
    public Collection<KeyPair> loadKeyPairs(String resourceKey, FilePasswordProvider passwordProvider, List<String> lines)
            throws IOException, GeneralSecurityException {
        Collection<KeyPair> keyPairs = Collections.emptyList();
        List<String> beginMarkers = getBeginners();
        List<List<String>> endMarkers = getEndingMarkers();
        for (Map.Entry<Integer, Integer> markerPos = KeyPairResourceParser.findMarkerLine(lines, beginMarkers); markerPos != null;) {
            int startIndex = markerPos.getKey();
            String startLine = lines.get(startIndex);
            startIndex++;

            int markerIndex = markerPos.getValue();
            List<String> ender = endMarkers.get(markerIndex);
            markerPos = KeyPairResourceParser.findMarkerLine(lines, startIndex, ender);
            if (markerPos == null) {
                throw new StreamCorruptedException("Missing end marker (" + ender + ") after line #" + startIndex);
            }

            int endIndex = markerPos.getKey();
            String endLine = lines.get(endIndex);
            Collection<KeyPair> kps =
                extractKeyPairs(resourceKey, startLine, endLine, passwordProvider, lines.subList(startIndex, endIndex));
            if (GenericUtils.isNotEmpty(kps)) {
                if (GenericUtils.isEmpty(keyPairs)) {
                    keyPairs = new LinkedList<>(kps);
                } else {
                    keyPairs.addAll(kps);
                }
            }

            // see if there are more
            markerPos = KeyPairResourceParser.findMarkerLine(lines, endIndex + 1, beginMarkers);
        }

        return keyPairs;
    }

    /**
     * Extracts the key pairs within a <U>single</U> delimited by markers block of lines. By
     * default cleans up the empty lines, joins them and converts them from BASE64
     *
     * @param resourceKey A hint as to the origin of the text lines
     * @param beginMarker The line containing the begin marker
     * @param endMarker The line containing the end marker
     * @param passwordProvider The {@link FilePasswordProvider} to use
     * in case the data is encrypted - may be {@code null} if no encrypted
     * @param lines The block of lines between the markers
     * @return The extracted {@link KeyPair}s - may be {@code null}/empty if none.
     * @throws IOException If failed to parse the data
     * @throws GeneralSecurityException If failed to generate the keys
     * @see #extractKeyPairs(String, String, String, FilePasswordProvider, byte[])
     */
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, List<String> lines)
                    throws IOException, GeneralSecurityException {
        return extractKeyPairs(resourceKey, beginMarker, endMarker, passwordProvider, KeyPairResourceParser.extractDataBytes(lines));
    }

    /**
     * @param resourceKey A hint as to the origin of the text lines
     * @param beginMarker The line containing the begin marker
     * @param endMarker The line containing the end marker
     * @param passwordProvider The {@link FilePasswordProvider} to use
     * in case the data is encrypted - may be {@code null} if no encrypted
     * @param bytes The decoded bytes from the lines containing the data
     * @return The extracted {@link KeyPair}s - may be {@code null}/empty if none.
     * @throws IOException If failed to parse the data
     * @throws GeneralSecurityException If failed to generate the keys
     * @see #extractKeyPairs(String, String, String, FilePasswordProvider, InputStream)
     */
    public Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, byte[] bytes)
                    throws IOException, GeneralSecurityException {
        if (log.isTraceEnabled()) {
            BufferUtils.dumpHex(getSimplifiedLogger(), Level.FINER, beginMarker, ':', 16, bytes);
        }

        try (InputStream bais = new ByteArrayInputStream(bytes)) {
            return extractKeyPairs(resourceKey, beginMarker, endMarker, passwordProvider, bais);
        }
    }

    /**
     * @param resourceKey A hint as to the origin of the text lines
     * @param beginMarker The line containing the begin marker
     * @param endMarker The line containing the end marker
     * @param passwordProvider The {@link FilePasswordProvider} to use
     * in case the data is encrypted - may be {@code null} if no encrypted
     * @param stream The decoded data {@link InputStream}
     * @return The extracted {@link KeyPair}s - may be {@code null}/empty if none.
     * @throws IOException If failed to parse the data
     * @throws GeneralSecurityException If failed to generate the keys
     */
    public abstract Collection<KeyPair> extractKeyPairs(
            String resourceKey, String beginMarker, String endMarker, FilePasswordProvider passwordProvider, InputStream stream)
                    throws IOException, GeneralSecurityException;
}
