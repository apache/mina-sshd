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

package org.apache.sshd.common.digest;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class DigestUtils {
    private DigestUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @param f The {@link Factory} to create the {@link Digest} to use
     * @param s The {@link String} to digest - ignored if {@code null}/empty,
     *          otherwise its UTF-8 representation is used as input for the fingerprint
     * @return The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     * @see #getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, String s) throws Exception {
        return getFingerPrint(f, s, StandardCharsets.UTF_8);
    }

    /**
     * @param f       The {@link Factory} to create the {@link Digest} to use
     * @param s       The {@link String} to digest - ignored if {@code null}/empty
     * @param charset The {@link Charset} to use in order to convert the
     *                string to its byte representation to use as input for the fingerprint
     * @return The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     */
    public static String getFingerPrint(Factory<? extends Digest> f, String s, Charset charset) throws Exception {
        return getFingerPrint(f.create(), s, charset);
    }

    /**
     * @param d The {@link Digest} to use
     * @param s The {@link String} to digest - ignored if {@code null}/empty,
     *          otherwise its UTF-8 representation is used as input for the fingerprint
     * @return The fingerprint - {@code null} if {@code null}/empty input
     * @throws Exception If failed to calculate the digest
     * @see #getFingerPrint(Digest, String, Charset)
     */
    public static String getFingerPrint(Digest d, String s) throws Exception {
        return getFingerPrint(d, s, StandardCharsets.UTF_8);
    }

    /**
     * @param d       The {@link Digest} to use
     * @param s       The {@link String} to digest - ignored if {@code null}/empty
     * @param charset The {@link Charset} to use in order to convert the
     *                string to its byte representation to use as input for the fingerprint
     * @return The fingerprint - {@code null} if {@code null}/empty input
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
     * @param f   The {@link Factory} to create the {@link Digest} to use
     * @param buf The data buffer to be fingerprint-ed
     * @return The fingerprint - {@code null} if empty data buffer
     * @throws Exception If failed to calculate the fingerprint
     * @see #getFingerPrint(Factory, byte[], int, int)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, byte... buf) throws Exception {
        return getFingerPrint(f, buf, 0, GenericUtils.length(buf));
    }

    /**
     * @param f      The {@link Factory} to create the {@link Digest} to use
     * @param buf    The data buffer to be fingerprint-ed
     * @param offset The offset of the data in the buffer
     * @param len    The length of data - ignored if non-positive
     * @return The fingerprint - {@code null} if non-positive length
     * @throws Exception If failed to calculate the fingerprint
     */
    public static String getFingerPrint(Factory<? extends Digest> f, byte[] buf, int offset, int len) throws Exception {
        return getFingerPrint(f.create(), buf, offset, len);
    }

    /**
     * @param d   The {@link Digest} to use
     * @param buf The data buffer to be fingerprint-ed
     * @return The fingerprint - {@code null} if empty data buffer
     * @throws Exception If failed to calculate the fingerprint
     * @see #getFingerPrint(Digest, byte[], int, int)
     */
    public static String getFingerPrint(Digest d, byte... buf) throws Exception {
        return getFingerPrint(d, buf, 0, GenericUtils.length(buf));
    }

    /**
     * @param d      The {@link Digest} to use
     * @param buf    The data buffer to be fingerprint-ed
     * @param offset The offset of the data in the buffer
     * @param len    The length of data - ignored if non-positive
     * @return The fingerprint - {@code null} if non-positive length
     * @throws Exception If failed to calculate the fingerprint
     */
    public static String getFingerPrint(Digest d, byte[] buf, int offset, int len) throws Exception {
        if (len <= 0) {
            return null;
        }

        d.init();
        d.update(buf, offset, len);

        byte[] data = d.digest();
        return BufferUtils.printHex(data, 0, data.length, ':');
    }


}
