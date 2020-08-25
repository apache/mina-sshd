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

package org.apache.sshd.client.config.hosts;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KnownHostHashValue {
    /**
     * Character used to indicate a hashed host pattern
     */
    public static final char HASHED_HOST_DELIMITER = '|';

    public static final NamedFactory<Mac> DEFAULT_DIGEST = KnownHostDigest.SHA1;

    private NamedFactory<Mac> digester = DEFAULT_DIGEST;
    private byte[] saltValue;
    private byte[] digestValue;

    public KnownHostHashValue() {
        super();
    }

    public NamedFactory<Mac> getDigester() {
        return digester;
    }

    public void setDigester(NamedFactory<Mac> digester) {
        this.digester = digester;
    }

    public byte[] getSaltValue() {
        return saltValue;
    }

    public void setSaltValue(byte[] saltValue) {
        this.saltValue = saltValue;
    }

    public byte[] getDigestValue() {
        return digestValue;
    }

    public void setDigestValue(byte[] digestValue) {
        this.digestValue = digestValue;
    }

    /**
     * Checks if the host matches the hash
     *
     * @param  host             The host name/address - ignored if {@code null}/empty
     * @param  port             The access port - ignored if non-positive or SSH default
     * @return                  {@code true} if host matches the hash
     * @throws RuntimeException If entry not properly initialized
     */
    public boolean isHostMatch(String host, int port) {
        if (GenericUtils.isEmpty(host)) {
            return false;
        }

        try {
            byte[] expected = getDigestValue();
            byte[] actual = calculateHashValue(host, port, getDigester(), getSaltValue());
            return Arrays.equals(expected, actual);
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new RuntimeSshException(
                    "Failed (" + t.getClass().getSimpleName() + ")" + " to calculate hash value: " + t.getMessage(), t);
        }
    }

    @Override
    public String toString() {
        if ((getDigester() == null) || NumberUtils.isEmpty(getSaltValue()) || NumberUtils.isEmpty(getDigestValue())) {
            return Objects.toString(getDigester(), null)
                   + "-" + BufferUtils.toHex(':', getSaltValue())
                   + "-" + BufferUtils.toHex(':', getDigestValue());
        }

        try {
            return append(new StringBuilder(Byte.MAX_VALUE), this).toString();
        } catch (IOException | RuntimeException e) { // unexpected
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    // see http://nms.lcs.mit.edu/projects/ssh/README.hashed-hosts
    public static byte[] calculateHashValue(String host, int port, Factory<? extends Mac> factory, byte[] salt)
            throws Exception {
        return calculateHashValue(host, port, factory.create(), salt);
    }

    public static byte[] calculateHashValue(String host, int port, Mac mac, byte[] salt) throws Exception {
        mac.init(salt);

        String hostPattern = createHostPattern(host, port);
        byte[] hostBytes = hostPattern.getBytes(StandardCharsets.UTF_8);
        mac.update(hostBytes);
        return mac.doFinal();
    }

    public static String createHostPattern(String host, int port) {
        if (SshConstants.TO_EFFECTIVE_PORT.applyAsInt(port) == SshConstants.DEFAULT_PORT) {
            return host;
        }

        try {
            return appendHostPattern(new StringBuilder(host.length() + 8 /* port if necessary */), host, port).toString();
        } catch (IOException e) {
            throw new RuntimeException(
                    "Unexpected (" + e.getClass().getSimpleName() + ") failure" + " to generate host pattern of " + host + ":"
                                       + port + ": " + e.getMessage(),
                    e);
        }
    }

    public static <A extends Appendable> A appendHostPattern(A sb, String host, int port) throws IOException {
        boolean nonDefaultPort = SshConstants.TO_EFFECTIVE_PORT.applyAsInt(port) != SshConstants.DEFAULT_PORT;
        if (nonDefaultPort) {
            sb.append(HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_START_DELIM);
        }
        sb.append(host);
        if (nonDefaultPort) {
            sb.append(HostPatternsHolder.NON_STANDARD_PORT_PATTERN_ENCLOSURE_END_DELIM);
            sb.append(HostPatternsHolder.PORT_VALUE_DELIMITER);
            sb.append(Integer.toString(port));
        }
        return sb;
    }

    public static <A extends Appendable> A append(A sb, KnownHostHashValue hashValue) throws IOException {
        return (hashValue == null)
                ? sb : append(sb, hashValue.getDigester(), hashValue.getSaltValue(), hashValue.getDigestValue());
    }

    public static <A extends Appendable> A append(A sb, NamedResource factory, byte[] salt, byte[] digest) throws IOException {
        Base64.Encoder encoder = Base64.getEncoder();
        sb.append(HASHED_HOST_DELIMITER).append(factory.getName());
        sb.append(HASHED_HOST_DELIMITER).append(encoder.encodeToString(salt));
        sb.append(HASHED_HOST_DELIMITER).append(encoder.encodeToString(digest));
        return sb;
    }

    public static KnownHostHashValue parse(String patternString) {
        String pattern = GenericUtils.replaceWhitespaceAndTrim(patternString);
        return parse(pattern, GenericUtils.isEmpty(pattern) ? null : new KnownHostHashValue());
    }

    public static <V extends KnownHostHashValue> V parse(String patternString, V value) {
        String pattern = GenericUtils.replaceWhitespaceAndTrim(patternString);
        if (GenericUtils.isEmpty(pattern)) {
            return value;
        }

        String[] components = GenericUtils.split(pattern, HASHED_HOST_DELIMITER);
        ValidateUtils.checkTrue(components.length == 4 /* 1st one is empty */, "Invalid hash pattern (insufficient data): %s",
                pattern);
        ValidateUtils.checkTrue(GenericUtils.isEmpty(components[0]), "Invalid hash pattern (unexpected extra data): %s",
                pattern);

        NamedFactory<Mac> factory = ValidateUtils.checkNotNull(KnownHostDigest.fromName(components[1]),
                "Invalid hash pattern (unknown digest): %s", pattern);
        Base64.Decoder decoder = Base64.getDecoder();
        value.setDigester(factory);
        value.setSaltValue(decoder.decode(components[2]));
        value.setDigestValue(decoder.decode(components[3]));
        return value;
    }
}
