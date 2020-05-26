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
package org.apache.sshd.util.test;

import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * A test {@link PasswordAuthenticator} that accepts an authentication attempt if the username is not {@code null} and
 * same as password
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BogusPasswordAuthenticator extends AbstractLoggingBean implements PasswordAuthenticator {
    public static final BogusPasswordAuthenticator INSTANCE = new BogusPasswordAuthenticator();

    public BogusPasswordAuthenticator() {
        super();
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session) {
        boolean result = (username != null) && username.equals(password);
        if (log.isDebugEnabled()) {
            log.debug("authenticate({}) {} / {} - success={}",
                    session, username, password, result);
        }

        return result;
    }
}
