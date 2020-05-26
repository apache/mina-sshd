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

package org.apache.sshd.server.session;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Provides a way to implement proxied connections where some metadata about the client is sent <U>before</U> the actual
 * SSH protocol is executed - e.g., the <A HREF=@http://www.haproxy.org/download/1.6/doc/proxy-protocol.txt">PROXY
 * protocol</A>.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ServerProxyAcceptor {
    /**
     * Invoked <U>before</U> any attempt is made to retrieve the SSH client identification data of the standard SSH
     * protocol. The implementor should extract whatever data it needs from the data buffer. <B>Note:</B> the method may
     * be called <U>several times</U> for the <U>same</U> session even though the original proxy data was successfully
     * extracted. This happens in case the client identification line following it is incomplete and thus requires
     * waiting for more incoming packets.
     *
     * @param  session   The {@link ServerSession} instance
     * @param  buffer    The received data {@link Buffer} - if not the 1st time this method is called because data was
     *                   lacking on last invocation, then the buffer is guaranteed to contain the data from all the
     *                   previous incomplete invocations plus any new received data. If not enough information is
     *                   available, the buffer's read position should be restored to its original value when the method
     *                   was invoked.
     * @return           {@code true} if successfully extracted the remote client peer meta-data, {@code false} if more
     *                   data is required. Upon successful return the buffer read position is assumed to indicate the
     *                   first character of the SSH identification line
     * @throws Exception If failed to correctly extract and parse the meta-data, in which case the session will be
     *                   closed
     */
    boolean acceptServerProxyMetadata(ServerSession session, Buffer buffer) throws Exception;
}
