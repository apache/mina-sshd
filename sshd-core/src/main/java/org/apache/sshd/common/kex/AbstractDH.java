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
package org.apache.sshd.common.kex;

import java.math.BigInteger;

import org.apache.sshd.common.Digest;

/**
 * Base class for the Diffie-Hellman key agreement.
 * 
 */
public abstract class AbstractDH {
    protected BigInteger K; // shared secret key
    private byte[] K_array;

    protected AbstractDH() {
    }

    public static AbstractDH getInstance(String algo) throws Exception {
        if (algo.startsWith("ecdh-sha2-")) {
            return new ECDH();
        } else {
            return new DH();
        }
    }

    public abstract void setF(byte[] e);

    public abstract byte[] getE() throws Exception;

    protected abstract byte[] calculateK() throws Exception;

    public byte[] getK() throws Exception {
        if (K == null) {
            K_array = calculateK();
            K = new BigInteger(K_array);
        }
        return K_array;
    }

    public abstract Digest getHash() throws Exception;

    // The shared secret returned by KeyAgreement.generateSecret() is
    // a byte array, which can (by chance, roughly 1 out of 256 times)
    // begin with zero byte (some JCE providers might strip this, though).
    // In SSH, the shared secret is an integer, so we need to strip
    // the leading zero(es).
    protected static byte[] stripLeadingZeroes(byte[] x) {
        int i = 0;
        while ((i < x.length - 1) && (x[i] == 0)) {
            i++;
        }
        byte[] ret = new byte[x.length - i];
        System.arraycopy(x, i, ret, 0, ret.length);
        return ret;
    }
}
