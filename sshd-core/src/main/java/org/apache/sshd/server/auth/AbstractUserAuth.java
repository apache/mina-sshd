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
package org.apache.sshd.server.auth;

import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 */
public abstract class AbstractUserAuth implements UserAuth {

    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    protected ServerSession session;
    protected String service;
    protected String username;

    public String getUserName() {
        return username;
    }

    public String getService() {
        return service;
    }

    public Boolean auth(ServerSession session, String username, String service, Buffer buffer) throws Exception {
        this.session = session;
        this.username = username;
        this.service = service;
        return doAuth(buffer, true);
    }

    public Boolean next(Buffer buffer) throws Exception {
        return doAuth(buffer, false);
    }

    public void destroy() {
    }

    protected abstract Boolean doAuth(Buffer buffer, boolean init) throws Exception;

}
