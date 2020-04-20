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
package org.apache.sshd.common.kex;

import javax.crypto.KeyAgreement;

import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.NumberUtils;

/**
 * Base class for the Diffie-Hellman key agreement.
 */
public abstract class AbstractDH {
    protected KeyAgreement myKeyAgree;

    private byte[] k_array; // shared secret key
    private byte[] e_array; // public key used in the exchange

    protected AbstractDH() {
        super();
    }

    public abstract void setF(byte[] f);

    public boolean isPublicDataAvailable() {
        return e_array != null;
    }

    /**
     * Lazy-called by {@link #getE()} if the public key data has not been generated yet.
     *
     * @return           The calculated public key data
     * @throws Exception If failed to generate the relevant data
     */
    protected abstract byte[] calculateE() throws Exception;

    /**
     * @return           The local public key data
     * @throws Exception If failed to calculate it
     */
    public byte[] getE() throws Exception {
        if (e_array == null) {
            e_array = calculateE();
            checkKeyAgreementNecessity();
        }

        return e_array;
    }

    public boolean isSharedSecretAvailable() {
        return k_array != null;
    }

    /**
     * Lazy-called by {@link #getK()} if the shared secret data has not been calculated yet
     *
     * @return           The shared secret data
     * @throws Exception If failed to calculate it
     */
    protected abstract byte[] calculateK() throws Exception;

    /**
     * @return           The shared secret key
     * @throws Exception If failed to calculate it
     */
    public byte[] getK() throws Exception {
        if (k_array == null) {
            k_array = calculateK();
            checkKeyAgreementNecessity();
        }
        return k_array;
    }

    /**
     * Called after either public or private parts have been calculated in order to check if the key-agreement mediator
     * is still required. By default, if both public and private parts have been calculated then key-agreement mediator
     * is null-ified to enable GC for it.
     *
     * @see #getE()
     * @see #getK()
     */
    protected void checkKeyAgreementNecessity() {
        if ((e_array == null) || (k_array == null)) {
            return;
        }

        if (myKeyAgree != null) {
            myKeyAgree = null; // allow GC for key agreement object
        }
    }

    public abstract Digest getHash() throws Exception;

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[publicDataAvailable=" + isPublicDataAvailable()
               + ", sharedSecretAvailable=" + isSharedSecretAvailable()
               + "]";
    }

    /**
     * The shared secret returned by {@link javax.crypto.KeyAgreement#generateSecret()} is a byte array, which can (by
     * chance, roughly 1 out of 256 times) begin with zero byte (some JCE providers might strip this, though). In SSH,
     * the shared secret is an integer, so we need to strip the leading zero(es).
     *
     * @param  x                        The original array
     * @return                          An (possibly) sub-array guaranteed to start with a non-zero byte
     * @throws IllegalArgumentException If all zeroes array
     * @see                             <A HREF="https://issues.apache.org/jira/browse/SSHD-330">SSHD-330</A>
     */
    public static byte[] stripLeadingZeroes(byte[] x) {
        int length = NumberUtils.length(x);
        for (int i = 0; i < x.length; i++) {
            if (x[i] == 0) {
                continue;
            }

            if (i == 0) { // 1st byte is non-zero so nothing to do
                return x;
            }

            byte[] ret = new byte[length - i];
            System.arraycopy(x, i, ret, 0, ret.length);
            return ret;
        }

        // all zeroes
        throw new IllegalArgumentException("No non-zero values in generated secret");
    }
}
