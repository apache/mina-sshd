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

import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.Buffer;

/**
 * A global request handler.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface GlobalRequestHandler {

    /**
     * Process the ssh-connection global request.
     * If an exception is thrown, the ConnectionService will send a failure message if needed
     * and the request will be considered handled.
     *
     * @param connectionService
     * @param request
     * @param wantReply
     * @param buffer
     * @return <code>true</code> if the request was handled
     * @throws Exception
     */
    boolean process(ConnectionService connectionService, String request, boolean wantReply, Buffer buffer) throws Exception;

}
