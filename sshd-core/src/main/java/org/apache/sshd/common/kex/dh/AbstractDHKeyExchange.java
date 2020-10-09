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

package org.apache.sshd.common.kex.dh;

import java.math.BigInteger;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractDHKeyExchange extends AbstractLoggingBean implements KeyExchange {
    protected byte[] v_s;
    protected byte[] v_c;
    protected byte[] i_s;
    protected byte[] i_c;
    protected Digest hash;
    protected byte[] k;
    protected byte[] h;

    private byte[] e;
    private BigInteger eValue;
    private byte[] f;
    private BigInteger fValue;

    private final Session session;

    protected AbstractDHKeyExchange(Session session) {
        this.session = Objects.requireNonNull(session, "No session provided");
    }

    @Override
    public void init(byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        this.v_s = ValidateUtils.checkNotNullAndNotEmpty(v_s, "No v_s value");
        this.v_c = ValidateUtils.checkNotNullAndNotEmpty(v_c, "No v_c value");
        this.i_s = ValidateUtils.checkNotNullAndNotEmpty(i_s, "No i_s value");
        this.i_c = ValidateUtils.checkNotNullAndNotEmpty(i_c, "No i_c value");
    }

    @Override
    public Session getSession() {
        return session;
    }

    @Override
    public Digest getHash() {
        return hash;
    }

    @Override
    public byte[] getH() {
        return h;
    }

    @Override
    public byte[] getK() {
        return k;
    }

    protected byte[] getE() {
        return e;
    }

    protected BigInteger getEValue() {
        if (eValue == null) {
            eValue = BufferUtils.fromMPIntBytes(getE());
        }

        return eValue;
    }

    protected byte[] updateE(Buffer buffer) {
        return updateE(buffer.getMPIntAsBytes());
    }

    protected byte[] updateE(byte[] mpInt) {
        setE(mpInt);
        return mpInt;
    }

    protected void setE(byte[] e) {
        this.e = e;

        if (eValue != null) {
            eValue = null;  // force lazy re-initialization
        }
    }

    protected void validateEValue(BigInteger pValue) throws Exception {
        BigInteger value = Objects.requireNonNull(getEValue(), "No DH 'e' value set");
        if (!KeyExchange.isValidDHValue(value, pValue)) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: invalid DH 'e' value");
        }
    }

    protected byte[] getF() {
        return f;
    }

    protected BigInteger getFValue() {
        if (fValue == null) {
            fValue = BufferUtils.fromMPIntBytes(getF());
        }

        return fValue;
    }

    protected byte[] updateF(Buffer buffer) {
        return updateF(buffer.getMPIntAsBytes());
    }

    protected byte[] updateF(byte[] mpInt) {
        setF(mpInt);
        return mpInt;
    }

    protected void setF(byte[] f) {
        this.f = f;

        if (fValue != null) {
            fValue = null;  // force lazy re-initialization
        }
    }

    protected void validateFValue(BigInteger pValue) throws Exception {
        BigInteger value = Objects.requireNonNull(getFValue(), "No DH 'f' value set");
        if (!KeyExchange.isValidDHValue(value, pValue)) {
            throw new SshException(
                    SshConstants.SSH2_DISCONNECT_KEY_EXCHANGE_FAILED,
                    "Protocol error: invalid DH 'f' value");
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getName() + "]";
    }
}
