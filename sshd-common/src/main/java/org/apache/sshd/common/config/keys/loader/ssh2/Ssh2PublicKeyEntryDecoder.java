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

package org.apache.sshd.common.config.keys.loader.ssh2;

import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.TreeMap;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyTypeNamesSupport;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.config.keys.PublicKeyRawDataDecoder;
import org.apache.sshd.common.config.keys.PublicKeyRawDataReader;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceParser;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Decodes a public key file encoded according to <A HREF="https://tools.ietf.org/html/rfc4716">The Secure Shell (SSH)
 * Public Key File Format</A>
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Ssh2PublicKeyEntryDecoder
        implements PublicKeyRawDataDecoder<PublicKey>, PublicKeyEntryResolver,
        PublicKeyRawDataReader<PublicKey>, KeyTypeNamesSupport {
    public static final NavigableSet<String> SUPPORTED_KEY_TYPES = Collections.unmodifiableNavigableSet(
            GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                    KeyPairProvider.SSH_RSA, KeyPairProvider.SSH_DSS, KeyPairProvider.SSH_ED25519,
                    KeyPairProvider.ECDSA_SHA2_NISTP256, KeyPairProvider.ECDSA_SHA2_NISTP384,
                    KeyPairProvider.ECDSA_SHA2_NISTP521));

    public static final String BEGIN_MARKER = "BEGIN SSH2 PUBLIC KEY";
    public static final List<String> START_MARKERS = Collections.singletonList(BEGIN_MARKER);

    public static final String END_MARKER = "END SSH2 PUBLIC KEY";
    public static final List<String> STOP_MARKERS = Collections.singletonList(END_MARKER);

    /**
     * According to <A HREF="https://tools.ietf.org/html/rfc4716#section-3.3">RFC-4716 section 3.3</A>:
     *
     * <P>
     * <code>
     *      A line is continued if the last character in the line is a &quot;\&quot;.  If
     *      the last character of a line is a &quot;\&quot;, then the logical contents of
     *      the line are formed by removing the &quot;\&quot; and the line termination
     *      characters, and appending the contents of the next line.
     * </code>
     * </P>
     */
    public static final char HEADER_CONTINUATION_INDICATOR = '\\';

    public static final Ssh2PublicKeyEntryDecoder INSTANCE = new Ssh2PublicKeyEntryDecoder();

    public Ssh2PublicKeyEntryDecoder() {
        super();
    }

    @Override
    public NavigableSet<String> getSupportedKeyTypes() {
        return SUPPORTED_KEY_TYPES;
    }

    @Override
    public PublicKey resolve(
            SessionContext session, String keyType, byte[] keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        ValidateUtils.checkNotNullAndNotEmpty(keyType, "No key type provided");
        Collection<String> supported = getSupportedKeyTypes();
        if ((GenericUtils.size(supported) > 0) && supported.contains(keyType)) {
            return decodePublicKey(session, keyType, keyData, headers);
        }

        throw new InvalidKeySpecException("resolve(" + keyType + ") not in listed supported types: " + supported);
    }

    @Override
    public PublicKey decodePublicKey(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        return decodePublicKeyByType(session, keyType, keyData, headers);
    }

    @Override
    public PublicKey decodePublicKeyByType(
            SessionContext session, String keyType, InputStream keyData, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        PublicKeyEntryDecoder<?, ?> decoder = KeyUtils.getPublicKeyEntryDecoder(keyType);
        if (decoder == null) {
            throw new InvalidKeySpecException("No decoder for key type=" + keyType);
        }

        return decoder.decodePublicKeyByType(session, keyType, keyData, headers);
    }

    @Override
    public PublicKey readPublicKey(SessionContext session, NamedResource resourceKey, List<String> lines)
            throws IOException, GeneralSecurityException {
        Map.Entry<Integer, Integer> markerPos = KeyPairResourceParser.findMarkerLine(lines, START_MARKERS);
        if (markerPos == null) {
            return null; // be lenient
        }

        int startIndex = markerPos.getKey();
        String startLine = lines.get(startIndex);
        startIndex++; // skip the starting marker

        markerPos = KeyPairResourceParser.findMarkerLine(lines, startIndex, STOP_MARKERS);
        if (markerPos == null) {
            throw new StreamCorruptedException("Missing end marker (" + END_MARKER + ") after line #" + startIndex);
        }

        int endIndex = markerPos.getKey();
        String endLine = lines.get(endIndex);
        Map.Entry<? extends Map<String, String>, ? extends List<String>> result = separateDataLinesFromHeaders(
                session, resourceKey, startLine, endLine, lines.subList(startIndex, endIndex));
        Map<String, String> headers = result.getKey();
        List<String> dataLines = result.getValue();
        return readPublicKey(session, resourceKey, BEGIN_MARKER, END_MARKER,
                (dataLines == null) ? Collections.emptyList() : dataLines,
                (headers == null) ? Collections.emptyMap() : headers);
    }

    public PublicKey readPublicKey(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            List<String> lines, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        byte[] dataBytes = KeyPairResourceParser.extractDataBytes(lines);
        try {
            return readPublicKey(session, resourceKey, beginMarker, endMarker, dataBytes, headers);
        } finally {
            Arrays.fill(dataBytes, (byte) 0); // clean up sensitive data a.s.a.p.
        }
    }

    public PublicKey readPublicKey(
            SessionContext session, NamedResource resourceKey,
            String beginMarker, String endMarker,
            byte[] dataBytes, Map<String, String> headers)
            throws IOException, GeneralSecurityException {
        Map.Entry<String, Integer> result
                = KeyEntryResolver.decodeString(dataBytes, KeyPairResourceLoader.MAX_KEY_TYPE_NAME_LENGTH);
        String keyType = result.getKey();
        return resolve(session, keyType, dataBytes, headers);
    }

    protected Map.Entry<Map<String, String>, List<String>> separateDataLinesFromHeaders(
            SessionContext session, NamedResource resourceKey, String startLine, String endLine, List<String> lines)
            throws IOException, GeneralSecurityException {
        // According to RFC-4716: The Header-tag is case-insensitive
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        int len = lines.size();
        for (int index = 0; index < len; index++) {
            String l = lines.get(index);
            l = l.trim();
            if (l.isEmpty()) {
                continue;
            }

            int pos = l.indexOf(':');
            // assume all the rest are data lines
            if (pos < 0) {
                return new SimpleImmutableEntry<>(headers, lines.subList(index, len));
            }

            String name = l.substring(0, pos).trim();
            String value = l.substring(pos + 1).trim();
            int vLen = value.length();
            if (value.charAt(vLen - 1) == HEADER_CONTINUATION_INDICATOR) {
                value = value.substring(0, vLen - 1);
                for (index++ /* skip current line */; index < len; index++) {
                    l = lines.get(index);
                    vLen = l.length();

                    if (l.charAt(vLen - 1) == HEADER_CONTINUATION_INDICATOR) {
                        value += l.substring(0, vLen - 1);
                        continue; // still continuation
                    }

                    value += l;
                    break; // no more continuations
                }
            }

            headers.put(name, value.trim());
        }

        throw new StreamCorruptedException(
                "No viable data lines found in " + resourceKey.getName() + " after " + startLine);
    }
}
