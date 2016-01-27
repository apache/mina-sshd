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
package org.apache.sshd.server.auth.pubkey;

import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * Caches the result per session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CachingPublicKeyAuthenticator extends AbstractLoggingBean implements PublickeyAuthenticator, SessionListener {

    protected final PublickeyAuthenticator authenticator;
    protected final Map<ServerSession, Map<PublicKey, Boolean>> cache = new ConcurrentHashMap<ServerSession, Map<PublicKey, Boolean>>();

    public CachingPublicKeyAuthenticator(PublickeyAuthenticator authenticator) {
        this.authenticator = ValidateUtils.checkNotNull(authenticator, "No delegate authenticator");
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        Map<PublicKey, Boolean> map = cache.get(session);
        if (map == null) {
            map = new ConcurrentHashMap<>();
            cache.put(session, map);
            session.addSessionListener(this);
        }

        Boolean result = map.get(key);
        if (result == null) {
            try {
                result = authenticator.authenticate(username, key, session);
            } catch (Error e) {
                log.warn("authenticate({}@{}) failed ({}) to consult delegate for {} key={}: {}",
                         username, session, e.getClass().getSimpleName(),
                         KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key), e.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("authenticate(" + username + "@" + session + ") delegate failure details", e);
                }

                throw new RuntimeSshException(e);
            }
            if (log.isDebugEnabled()) {
                log.debug("authenticate({}@{}) cache result={} for {} key={}",
                          username, session, result, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
            map.put(key, result);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("authenticate({}@{}) use cached result={} for {} key={}",
                          username, session, result, KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
            }
        }

        return result;
    }

    @Override
    public void sessionCreated(Session session) {
        // ignored
    }

    @Override
    public void sessionEvent(Session session, Event event) {
        // ignored
    }

    @Override
    public void sessionException(Session session, Throwable t) {
        if (log.isDebugEnabled()) {
            log.debug("sessionException({}) {}: {}", session, t.getClass().getSimpleName(), t.getMessage());
        }
        if (log.isTraceEnabled()) {
            log.trace("sessionException(" + session + ") details", t);
        }
        sessionClosed(session);
    }

    @Override
    public void sessionClosed(Session session) {
        Map<PublicKey, Boolean> map = cache.remove(session);
        if (map == null) {
            log.debug("sessionClosed({}) not cached", session);
        } else {
            log.debug("sessionClosed({}) removed from cache", session);
        }
        session.removeSessionListener(this);
    }
}
