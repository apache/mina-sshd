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

package org.apache.sshd.server.config;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.forward.TcpForwardingFilter;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="http://www.freebsd.org/cgi/man.cgi?query=sshd_config&sektion=5">sshd_config(5) section</A>
 */
public enum AllowTcpForwardingValue implements TcpForwardingFilter {
    ALL {
        @Override
        public boolean canListen(SshdSocketAddress address, Session session) {
            return true;
        }

        @Override
        public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
            return true;
        }
    },
    NONE {
        @Override
        public boolean canListen(SshdSocketAddress address, Session session) {
            return false;
        }

        @Override
        public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
            return false;
        }
    },
    LOCAL {
        @Override
        public boolean canListen(SshdSocketAddress address, Session session) {
            return true;
        }

        @Override
        public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
            return false;
        }
    },
    REMOTE {
        @Override
        public boolean canListen(SshdSocketAddress address, Session session) {
            return false;
        }

        @Override
        public boolean canConnect(Type type, SshdSocketAddress address, Session session) {
            return true;
        }
    };

    public static final Set<AllowTcpForwardingValue> VALUES
            = Collections.unmodifiableSet(EnumSet.allOf(AllowTcpForwardingValue.class));

    // NOTE: it also interprets "yes" as "all" and "no" as "none"
    public static AllowTcpForwardingValue fromString(String s) {
        if (GenericUtils.isEmpty(s)) {
            return null;
        }

        if ("yes".equalsIgnoreCase(s)) {
            return ALL;
        }

        if ("no".equalsIgnoreCase(s)) {
            return NONE;
        }

        for (AllowTcpForwardingValue v : VALUES) {
            if (s.equalsIgnoreCase(v.name())) {
                return v;
            }
        }

        return null;
    }
}
