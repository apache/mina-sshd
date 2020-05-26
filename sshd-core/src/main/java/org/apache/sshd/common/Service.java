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
package org.apache.sshd.common;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * See RFC 4253 [SSH-TRANS] and the SSH_MSG_SERVICE_REQUEST packet. Examples include &quot;ssh-userauth&quot; and
 * &quot;ssh-connection&quot; but developers are also free to implement their own custom service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Service extends SessionHolder<Session>, PropertyResolver, Closeable {
    @Override
    default PropertyResolver getParentPropertyResolver() {
        return getSession();
    }

    void start();

    /**
     * Service the request.
     *
     * @param  cmd       The incoming command type
     * @param  buffer    The {@link Buffer} containing optional command parameters
     * @throws Exception If failed to process the command
     */
    void process(int cmd, Buffer buffer) throws Exception;
}
