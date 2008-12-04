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
package org.apache.sshd.server;

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.session.ServerSession;

public interface UserAuth {

    /**
     * Try to authenticate the user.
     * This methods should return a non null object which is the user identity if
     * the authentication succeeded.  If the authentication failed, this method should
     * throw an exception.  If the authentication is still ongoing, a null value should
     * be returned.
     *
     * @param session the current ssh session
     * @param username the user trying to log in
     * @param buffer the request buffer containing parameters specific to this request
     *
     * @return the identity of the user or null if the authentication fails
     */
    Object auth(ServerSession session, String username, Buffer buffer) throws Exception;

}
