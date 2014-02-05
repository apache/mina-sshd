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
package org.apache.sshd.common;

import java.io.IOException;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.util.Buffer;

/**
 * See RFC 4253 [SSH-TRANS] and the SSH_MSG_SERVICE_REQUEST packet.  Examples include ssh-userauth
 * and ssh-connection but developers are also free to implement their own custom service.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Service extends Closeable {

    Session getSession();

    // TODO: this is specific to clients
    void start();

    /**
     * Service the request.
     * @param buffer
     * @throws Exception
     */
    void process(byte cmd, Buffer buffer) throws Exception;

    /**
     * Close the service.
     * @param immediately
     *
     */
    CloseFuture close(boolean immediately);

}
