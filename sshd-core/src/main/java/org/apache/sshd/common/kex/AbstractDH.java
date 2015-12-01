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

import java.math.BigInteger;

import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.util.NumberUtils;

/**
 * Base class for the Diffie-Hellman key agreement.
 */
public abstract class AbstractDH {

    protected BigInteger k; // shared secret key
    private byte[] k_array;

    protected AbstractDH() {
        super();
    }

    public abstract void setF(byte[] e);

    public abstract byte[] getE() throws Exception;

    protected abstract byte[] calculateK() throws Exception;

    public byte[] getK() throws Exception {
        if (k == null) {
            k_array = calculateK();
            k = new BigInteger(k_array);
        }
        return k_array;
    }

    public abstract Digest getHash() throws Exception;

    /**
     * The shared secret returned by {@link javax.crypto.KeyAgreement#generateSecret()}
     * is a byte array, which can (by chance, roughly 1 out of 256 times) begin
     * with zero byte (some JCE providers might strip this, though). In SSH,
     * the shared secret is an integer, so we need to strip the leading zero(es).
     *
     * @param x The original array
     * @return An (possibly) sub-array guaranteed to start with a non-zero byte
     * @throws IllegalArgumentException If all zeroes array
     * @see <A HREF="https://issues.apache.org/jira/browse/SSHD-330">SSHD-330</A>
     */
    public static byte[] stripLeadingZeroes(byte[] x) {
        int length = NumberUtils.length(x);
        for (int i = 0; i < x.length; i++) {
            if (x[i] == 0) {
                continue;
            }

            if (i == 0) {   // 1st byte is non-zero so nothing to do
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
