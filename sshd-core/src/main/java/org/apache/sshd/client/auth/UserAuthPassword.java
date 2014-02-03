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
package org.apache.sshd.client.auth;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.ClientSession;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.session.ClientUserAuthServiceNew;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class UserAuthPassword implements UserAuth {

    public static class Factory implements NamedFactory<UserAuth> {
        public String getName() {
            return "password";
        }
        public UserAuth create() {
            return new UserAuthPassword();
        }
    }

    protected final Logger log = LoggerFactory.getLogger(getClass());
    private ClientSession session;
    private String service;
    private Iterator<String> passwords;
    private String current;

    public void init(ClientSession session, String service, List<Object> identities) throws Exception {
        this.session = session;
        this.service = service;
        List<String> pwds = new ArrayList<String>();
        for (Object o : identities) {
            if (o instanceof String) {
                pwds.add((String) o);
            }
        }
        this.passwords = pwds.iterator();
    }

    public boolean process(Buffer buffer) throws Exception {
        // Send next key
        if (buffer == null) {
            if (passwords.hasNext()) {
                current = passwords.next();
                log.debug("Send SSH_MSG_USERAUTH_REQUEST for password");
                buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
                buffer.putString(session.getUsername());
                buffer.putString(service);
                buffer.putString("password");
                buffer.putByte((byte) 0);
                buffer.putString(current);
                session.writePacket(buffer);
                return true;
            }
            return false;
        }
        byte cmd = buffer.getByte();
        if (cmd == SshConstants.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
            String prompt = buffer.getString();
            String lang = buffer.getString();
            // TODO: prompt user for password change
            log.warn("Password change requested, but not supported");
            return false;
        }
        throw new IllegalStateException("Received unknown packet");
    }

    public void destroy() {
    }
}
