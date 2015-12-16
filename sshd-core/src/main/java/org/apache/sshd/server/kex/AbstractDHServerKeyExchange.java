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

package org.apache.sshd.server.kex;

import java.security.PublicKey;

import org.apache.sshd.common.kex.dh.AbstractDHKeyExchange;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractDHServerKeyExchange extends AbstractDHKeyExchange implements ServerSessionHolder {

    protected AbstractDHServerKeyExchange() {
        super();
    }

    @Override
    public final ServerSession getServerSession() {
        return (ServerSession) getSession();
    }

    @Override
    public void init(Session s, byte[] v_s, byte[] v_c, byte[] i_s, byte[] i_c) throws Exception {
        super.init(s, v_s, v_c, i_s, i_c);
        ValidateUtils.checkTrue(s instanceof ServerSession, "Using a server side KeyExchange on a client");
    }

    @Override
    public PublicKey getServerKey() {
        ServerSession session = getServerSession();
        return ValidateUtils.checkNotNull(session.getHostKey(), "No server key pair available").getPublic();
    }
}
