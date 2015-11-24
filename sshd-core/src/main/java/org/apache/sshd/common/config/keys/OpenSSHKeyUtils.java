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
package org.apache.sshd.common.config.keys;

import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.digest.DigestFactory;
import org.apache.sshd.common.util.Base64;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Utility class for keys
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class OpenSSHKeyUtils {

    /**
     * The default {@link Factory} of {@link Digest}s initialized
     * as the value of {@link #getDefaultFingerPrintFactory()}
     */
    public static final Factory<Digest> DEFAULT_FINGERPRINT_DIGEST_FACTORY = BuiltinDigests.sha256;

    private static final AtomicReference<Factory<? extends Digest>> DEFAULT_DIGEST_HOLDER =
            new AtomicReference<Factory<? extends Digest>>(DEFAULT_FINGERPRINT_DIGEST_FACTORY);

    private OpenSSHKeyUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    /**
     * @return The default {@link Factory} of {@link Digest}s used
     * by the {@link #getFingerPrint(PublicKey)} and {@link #getFingerPrint(String)}
     * methods
     * @see #setDefaultFingerPrintFactory(Factory)
     */
    public static Factory<? extends Digest> getDefaultFingerPrintFactory() {
        return DEFAULT_DIGEST_HOLDER.get();
    }

    /**
     * @param f The {@link Factory} of {@link Digest}s to be used - may
     *          not be {@code null}
     */
    public static void setDefaultFingerPrintFactory(Factory<? extends Digest> f) {
        DEFAULT_DIGEST_HOLDER.set(ValidateUtils.checkNotNull(f, "No digest factory"));
    }

    /**
     * @param key the public key - ignored if {@code null}
     * @return the fingerprint or {@code null} if no key.
     * <B>Note:</B> if exception encountered then returns the exception's simple class name
     * @throws Exception if cannot create fingerprint.
     * @see #getFingerPrint(Factory, PublicKey)
     */
    public static String getFingerPrint(PublicKey key) throws Exception {
        return getFingerPrint(getDefaultFingerPrintFactory(), key);
    }

    /**
     * @param f   The {@link Factory} to create the {@link Digest} to use
     * @param key the public key - ignored if {@code null}
     * @return the fingerprint or {@code null} if no key.
     * <B>Note:</B> if exception encountered then returns the exception's simple class name
     * @throws Exception if cannot create fingerprint.
     * @see #getFingerPrint(Digest, PublicKey)
     */
    public static String getFingerPrint(Factory<? extends Digest> f, PublicKey key) throws Exception {
        return getFingerPrint(f.create(), key);
    }

    /**
     * @param d   The {@link Digest} to use
     * @param key the public key - ignored if {@code null}
     * @return the fingerprint or {@code null} if no key.
     * @throws Exception if cannot create fingerprint.
     */
    public static String getFingerPrint(Digest d, PublicKey key) throws Exception {
        if (key == null) {
            return null;
        }

        Buffer buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(key);

        d.init();
        d.update(buffer.array(), 0, buffer.wpos());

        byte[] data = d.digest();

        String algo = d.getAlgorithm();
        if (BuiltinDigests.md5.getAlgorithm().equals(algo)) {
            return algo + ":" + BufferUtils.printHex(':', data);
        } else {
            return algo.replace("-", "").toUpperCase() + ":" + Base64.encodeToString(data).replaceAll("=", "");
        }
    }

    /**
     * @param expected The expected fingerprint if {@code null} or empty then returns a failure with the
     * default fingerprint.
     * @param key the public key - if {@code null} then returns null.
     * @return Pair<Boolean, String> - first is success indicator, second is actual fingerprint,
     * {@code null} if no key.
     */
    public static Pair<Boolean, String> checkFingerPrint(String expected, PublicKey key) throws Exception {
        if (key == null) {
            return null;
        }

        if (GenericUtils.isEmpty(expected)) {
            return new Pair<>(false, getFingerPrint(key));
        }

        String comps[] = GenericUtils.trimToEmpty(expected).split(":", 2);
        if (GenericUtils.length(comps) < 2) {
            return new Pair<>(false, getFingerPrint(key));
        }

        DigestFactory factory;
        // We know that all digests have a length > 2 - if 2 (or less) then assume a pure HEX value
        if (comps[0].length() > 2) {
            factory = BuiltinDigests.fromString(comps[0]);
            if (factory == null) {
                return new Pair<>(false, getFingerPrint(key));
            }
            expected = comps[0].toUpperCase() + ":" + comps[1];
        } else {
            factory = BuiltinDigests.md5;
            expected = factory.getName().toUpperCase() + ":" + expected;
        }

        String fingerprint = getFingerPrint(factory, key);
        boolean matches = BuiltinDigests.md5.getName().equals(factory.getName()) ? expected.equalsIgnoreCase(fingerprint) : expected.equals(fingerprint);
        return new Pair<>(matches, fingerprint);
    }

}
