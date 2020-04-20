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

package org.apache.sshd.common.digest;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.Objects;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class DigestUtils {
    private DigestUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param  algorithm The digest algorithm - never {@code null}/empty
     * @return           {@code true} if this digest algorithm is supported
     * @see              SecurityUtils#getMessageDigest(String)
     */
    public static boolean checkSupported(String algorithm) {
        ValidateUtils.checkNotNullAndNotEmpty(algorithm, "No algorithm");
        try {
            MessageDigest digest = SecurityUtils.getMessageDigest(algorithm);
            return digest != null; // just in case
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * @param  <D>     The generic type of digest factory
     * @param  algo    The required algorithm name - ignored if {@code null}/empty
     * @param  comp    The {@link Comparator} to use to compare algorithm names
     * @param  digests The factories to check - ignored if {@code null}/empty
     * @return         The first {@link DigestFactory} whose algorithm matches the required one according to the
     *                 comparator - {@code null} if no match found
     */
    public static <D extends Digest> D findDigestByAlgorithm(
            String algo, Comparator<? super String> comp, Collection<? extends D> digests) {
        if (GenericUtils.isEmpty(algo) || GenericUtils.isEmpty(digests)) {
            return null;
        }

        for (D d : digests) {
            if (comp.compare(algo, d.getAlgorithm()) == 0) {
                return d;
            }
        }

        return null;
    }

    /**
     * @param  <F>       The generic type of digest factory
     * @param  algo      The required algorithm name - ignored if {@code null}/empty
     * @param  comp      The {@link Comparator} to use to compare algorithm names
     * @param  factories The factories to check - ignored if {@code null}/empty
     * @return           The first {@link DigestFactory} whose algorithm matches the required one according to the
     *                   comparator - {@code null} if no match found
     */
    public static <F extends DigestFactory> F findFactoryByAlgorithm(
            String algo, Comparator<? super String> comp, Collection<? extends F> factories) {
        if (GenericUtils.isEmpty(algo) || GenericUtils.isEmpty(factories)) {
            return null;
        }

        for (F f : factories) {
            if (comp.compare(algo, f.getAlgorithm()) == 0) {
                return f;
            }
        }

        return null;
    }

    /**
     * @param  f         The {@link Factory} to create the {@link Digest} to use
     * @param  s         The {@link String} to digest - ignored if {@code null}/empty, otherwise its UTF-8
     *                   representation is used as input for the fingerprint
     * @return           The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     * @see              #getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, String s) throws Exception {
        return getFingerPrint(f, s, StandardCharsets.UTF_8);
    }

    /**
     * @param  f         The {@link Factory} to create the {@link Digest} to use
     * @param  s         The {@link String} to digest - ignored if {@code null}/empty
     * @param  charset   The {@link Charset} to use in order to convert the string to its byte representation to use as
     *                   input for the fingerprint
     * @return           The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     */
    public static String getFingerPrint(Factory<? extends Digest> f, String s, Charset charset) throws Exception {
        return getFingerPrint(Objects.requireNonNull(f, "No factory").create(), s, charset);
    }

    /**
     * @param  d         The {@link Digest} to use
     * @param  s         The {@link String} to digest - ignored if {@code null}/empty, otherwise its UTF-8
     *                   representation is used as input for the fingerprint
     * @return           The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     * @see              #getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Digest d, String s) throws Exception {
        return getFingerPrint(d, s, StandardCharsets.UTF_8);
    }

    /**
     * @param  d         The {@link Digest} to use
     * @param  s         The {@link String} to digest - ignored if {@code null}/empty
     * @param  charset   The {@link Charset} to use in order to convert the string to its byte representation to use as
     *                   input for the fingerprint
     * @return           The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     */
    public static String getFingerPrint(Digest d, String s, Charset charset) throws Exception {
        if (GenericUtils.isEmpty(s)) {
            return null;
        } else {
            return DigestUtils.getFingerPrint(d, s.getBytes(charset));
        }
    }

    /**
     * @param  f         The {@link Factory} to create the {@link Digest} to use
     * @param  buf       The data buffer to be fingerprint-ed
     * @return           The fingerprint - {@code null} if empty data buffer
     * @throws Exception If failed to calculate the fingerprint
     * @see              #getFingerPrint(Factory, byte[], int, int)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, byte... buf) throws Exception {
        return getFingerPrint(f, buf, 0, NumberUtils.length(buf));
    }

    /**
     * @param  f         The {@link Factory} to create the {@link Digest} to use
     * @param  buf       The data buffer to be fingerprint-ed
     * @param  offset    The offset of the data in the buffer
     * @param  len       The length of data - ignored if non-positive
     * @return           The fingerprint - {@code null} if non-positive length
     * @throws Exception If failed to calculate the fingerprint
     */
    public static String getFingerPrint(Factory<? extends Digest> f, byte[] buf, int offset, int len) throws Exception {
        return getFingerPrint(Objects.requireNonNull(f, "No factory").create(), buf, offset, len);
    }

    /**
     * @param  d         The {@link Digest} to use
     * @param  buf       The data buffer to be fingerprint-ed
     * @return           The fingerprint - {@code null} if empty data buffer
     * @throws Exception If failed to calculate the fingerprint
     * @see              #getFingerPrint(Digest, byte[], int, int)
     */
    public static String getFingerPrint(Digest d, byte... buf) throws Exception {
        return getFingerPrint(d, buf, 0, NumberUtils.length(buf));
    }

    /**
     * @param  d         The {@link Digest} to use
     * @param  buf       The data buffer to be fingerprint-ed
     * @param  offset    The offset of the data in the buffer
     * @param  len       The length of data - ignored if non-positive
     * @return           The fingerprint - {@code null} if non-positive length
     * @throws Exception If failed to calculate the fingerprint
     * @see              #getRawFingerprint(Digest, byte[], int, int)
     */
    public static String getFingerPrint(Digest d, byte[] buf, int offset, int len) throws Exception {
        if (len <= 0) {
            return null;
        }

        byte[] data = getRawFingerprint(d, buf, offset, len);
        String algo = d.getAlgorithm();
        if (BuiltinDigests.md5.getAlgorithm().equals(algo)) {
            return algo + ":" + BufferUtils.toHex(':', data).toLowerCase();
        }

        Base64.Encoder encoder = Base64.getEncoder();
        return algo.replace("-", "").toUpperCase() + ":" + encoder.encodeToString(data).replaceAll("=", "");
    }

    public static byte[] getRawFingerprint(Digest d, byte... buf) throws Exception {
        return getRawFingerprint(d, buf, 0, NumberUtils.length(buf));
    }

    public static byte[] getRawFingerprint(Digest d, byte[] buf, int offset, int len) throws Exception {
        if (len <= 0) {
            return null;
        }

        Objects.requireNonNull(d, "No digest").init();
        d.update(buf, offset, len);

        return d.digest();
    }
}
