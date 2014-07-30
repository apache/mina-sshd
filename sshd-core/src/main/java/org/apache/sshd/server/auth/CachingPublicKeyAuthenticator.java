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

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.Session;
import org.apache.sshd.common.SessionListener;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CachingPublicKeyAuthenticator implements PublickeyAuthenticator, SessionListener {

    protected final PublickeyAuthenticator authenticator;
    protected final Map<ServerSession, Map<PublicKey, Boolean>> cache = new ConcurrentHashMap<ServerSession, Map<PublicKey, Boolean>>();

    public CachingPublicKeyAuthenticator(PublickeyAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        Map<PublicKey, Boolean> map = cache.get(session);
        if (map == null) {
            map = new HashMap<PublicKey, Boolean>();
            cache.put(session, map);
            session.addListener(this);
        }
        if (map.containsKey(key)) {
            return map.get(key);
        }
        boolean result = authenticator.authenticate(username, key, session);
        map.put(key, result);
        return result;
    }

    public void sessionCreated(Session session) {
    }

    public void sessionEvent(Session session, Event event) {
    }

    public void sessionClosed(Session session) {
        cache.remove(session);
    }
}
