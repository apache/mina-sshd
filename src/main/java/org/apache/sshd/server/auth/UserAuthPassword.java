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

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
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

    public Object auth(ServerSession session, String username, Buffer buffer) throws Exception {
        boolean newPassword = buffer.getBoolean();
        if (newPassword) {
            throw new IllegalStateException("Password changes are not supported");
        }
        String password = buffer.getString();
        return checkPassword(session, username, password);
    }

    private Object checkPassword(ServerSession session, String username, String password) throws Exception {
        PasswordAuthenticator auth = session.getServerFactoryManager().getPasswordAuthenticator();
        if (auth != null) {
            Object identity = auth.authenticate(username, password);
            if (identity != null) {
                return identity;
            } else {
                throw new Exception("Authentication failed: bad username or password supplied");
            }
        }
        throw new Exception("No PasswordAuthenticator configured");
    }

}
