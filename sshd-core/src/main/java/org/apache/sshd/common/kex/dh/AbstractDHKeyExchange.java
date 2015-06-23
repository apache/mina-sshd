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

package org.apache.sshd.common.kex.dh;

import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.session.AbstractSession;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractDHKeyExchange extends AbstractLoggingBean implements KeyExchange {
    private AbstractSession session;
    protected byte[] V_S;
    protected byte[] V_C;
    protected byte[] I_S;
    protected byte[] I_C;
    protected Digest hash;
    protected byte[] e;
    protected byte[] f;
    protected byte[] K;
    protected byte[] H;

    protected AbstractDHKeyExchange() {
        super();
    }

    @Override
    public void init(AbstractSession s, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        this.session = ValidateUtils.checkNotNull(s, "No session", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.V_S = ValidateUtils.checkNotNullAndNotEmpty(V_S, "No V_S value", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.V_C = ValidateUtils.checkNotNullAndNotEmpty(V_C, "No V_C value", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.I_S = ValidateUtils.checkNotNullAndNotEmpty(I_S, "No I_S value", GenericUtils.EMPTY_OBJECT_ARRAY);
        this.I_C = ValidateUtils.checkNotNullAndNotEmpty(I_C, "No I_C value", GenericUtils.EMPTY_OBJECT_ARRAY);
    }

    public AbstractSession getSession() {
        return session;
    }

    @Override
    public Digest getHash() {
        return hash;
    }

    @Override
    public byte[] getH() {
        return H;
    }

    @Override
    public byte[] getK() {
        return K;
    }
}
