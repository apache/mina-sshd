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

package org.apache.sshd.common.forward;

import java.util.Collection;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LocalForwardingEntry extends SshdSocketAddress {
    private static final long serialVersionUID = 423661570180889621L;
    private final String alias;

    public LocalForwardingEntry(String hostName, String alias, int port) {
        super(hostName, port);
        this.alias = ValidateUtils.checkNotNullAndNotEmpty(alias, "No host alias");
    }

    public String getAlias() {
        return alias;
    }

    @Override
    protected boolean isEquivalent(SshdSocketAddress that) {
        if (super.isEquivalent(that) && (that instanceof LocalForwardingEntry)) {
            LocalForwardingEntry entry = (LocalForwardingEntry) that;
            if (Objects.equals(this.getAlias(), entry.getAlias())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public int hashCode() {
        return super.hashCode() + Objects.hashCode(getAlias());
    }

    @Override
    public String toString() {
        return super.toString() + " - " + getAlias();
    }

    /**
     * @param host    The host - ignored if {@code null}/empty - i.e., no match reported
     * @param port    The port - ignored if non-positive - i.e., no match reported
     * @param entries The {@link Collection} of {@link LocalForwardingEntry} to check
     *                - ignored if {@code null}/empty - i.e., no match reported
     * @return The <U>first</U> entry whose host or alias matches the host name - case
     * <U>sensitive</U> <B>and</B> has a matching port - {@code null} if no match found
     */
    public static final LocalForwardingEntry findMatchingEntry(String host, int port, Collection<? extends LocalForwardingEntry> entries) {
        if (GenericUtils.isEmpty(host) || (port <= 0) || (GenericUtils.isEmpty(entries))) {
            return null;
        }

        for (LocalForwardingEntry e : entries) {
            if ((port == e.getPort()) && (host.equals(e.getHostName()) || host.equals(e.getAlias()))) {
                return e;
            }
        }

        return null;    // no match found
    }
}