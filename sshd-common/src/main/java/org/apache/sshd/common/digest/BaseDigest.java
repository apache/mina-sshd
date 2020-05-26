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

import java.security.MessageDigest;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Base class for Digest algorithms based on the JCE provider.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BaseDigest implements Digest {

    private final String algorithm;
    private final int bsize;
    private int h;
    private String s;
    private MessageDigest md;

    /**
     * Create a new digest using the given algorithm and block size. The initialization and creation of the underlying
     * {@link MessageDigest} object will be done in the {@link #init()} method.
     *
     * @param algorithm the JCE algorithm to use for this digest
     * @param bsize     the block size of this digest
     */
    public BaseDigest(String algorithm, int bsize) {
        this.algorithm = ValidateUtils.checkNotNullAndNotEmpty(algorithm, "No algorithm");
        ValidateUtils.checkTrue(bsize > 0, "Invalid block size: %d", bsize);
        this.bsize = bsize;
    }

    @Override
    public final String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getBlockSize() {
        return bsize;
    }

    @Override
    public void init() throws Exception {
        this.md = SecurityUtils.getMessageDigest(getAlgorithm());
    }

    @Override
    public void update(byte[] data) throws Exception {
        update(data, 0, NumberUtils.length(data));
    }

    @Override
    public void update(byte[] data, int start, int len) throws Exception {
        Objects.requireNonNull(md, "Digest not initialized").update(data, start, len);
    }

    /**
     * @return The current {@link MessageDigest} - may be {@code null} if {@link #init()} not called
     */
    protected MessageDigest getMessageDigest() {
        return md;
    }

    @Override
    public byte[] digest() throws Exception {
        return Objects.requireNonNull(md, "Digest not initialized").digest();
    }

    @Override
    public int hashCode() {
        synchronized (this) {
            if (h == 0) {
                h = Objects.hashCode(getAlgorithm()) + getBlockSize();
                if (h == 0) {
                    h = 1;
                }
            }
        }

        return h;
    }

    @Override
    public int compareTo(Digest that) {
        if (that == null) {
            return -1; // push null(s) to end
        } else if (this == that) {
            return 0;
        }

        String thisAlg = getAlgorithm();
        String thatAlg = that.getAlgorithm();
        int nRes = GenericUtils.safeCompare(thisAlg, thatAlg, false);
        if (nRes != 0) {
            return nRes; // debug breakpoint
        }

        nRes = Integer.compare(this.getBlockSize(), that.getBlockSize());
        if (nRes != 0) {
            return nRes; // debug breakpoint
        }

        return 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        int nRes = compareTo((Digest) obj);
        return nRes == 0;
    }

    @Override
    public String toString() {
        synchronized (this) {
            if (s == null) {
                s = getClass().getSimpleName() + "[" + getAlgorithm() + ":" + getBlockSize() + "]";
            }
        }

        return s;
    }
}
