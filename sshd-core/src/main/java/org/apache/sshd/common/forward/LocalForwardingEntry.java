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

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LocalForwardingEntry {
    private final SshdSocketAddress local;
    private final SshdSocketAddress bound;
    private final SshdSocketAddress combined;

    public LocalForwardingEntry(SshdSocketAddress local, InetSocketAddress bound) {
        this(local, new SshdSocketAddress(bound));
    }

    public LocalForwardingEntry(SshdSocketAddress local, SshdSocketAddress bound) {
        this.local = Objects.requireNonNull(local, "No local address provided");
        this.bound = Objects.requireNonNull(bound, "No bound address provided");
        this.combined = resolveCombinedBoundAddress(local, bound);
    }

    /**
     * @return The original requested local address for binding
     */
    public SshdSocketAddress getLocalAddress() {
        return local;
    }

    /**
     * @return The actual bound address
     */
    public SshdSocketAddress getBoundAddress() {
        return bound;
    }

    /**
     * A combined address using the following logic:
     * <UL>
     * <LI>If original requested local binding has a specific port and non-wildcard address then use the local binding
     * as-is</LI>
     *
     * <LI>If original requested local binding has a specific address but no specific port, then combine its address
     * with the actual auto-allocated port at binding.</LI>
     *
     * <LI>If original requested local binding has neither a specific address nor a specific port then use the effective
     * bound address.</LI>
     * <UL>
     *
     * @return Combined result
     */
    public SshdSocketAddress getCombinedBoundAddress() {
        return combined;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (o == this) {
            return true;
        }
        if (getClass() != o.getClass()) {
            return false;
        }

        LocalForwardingEntry other = (LocalForwardingEntry) o;
        return Objects.equals(getCombinedBoundAddress(), other.getCombinedBoundAddress());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getCombinedBoundAddress());
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[local=" + getLocalAddress()
               + ", bound=" + getBoundAddress()
               + ", combined=" + getCombinedBoundAddress() + "]";
    }

    public static SshdSocketAddress resolveCombinedBoundAddress(SshdSocketAddress local, SshdSocketAddress bound) {
        int localPort = local.getPort();
        int boundPort = bound.getPort();
        if ((localPort > 0) && (localPort != boundPort)) {
            throw new IllegalArgumentException("Mismatched ports for local (" + local + ") vs. bound (" + bound + ") entry");
        }

        if (Objects.equals(local, bound)) {
            return local;
        }

        String localName = local.getHostName();
        boolean wildcardLocal = SshdSocketAddress.isWildcardAddress(localName);
        if (wildcardLocal) {
            return bound;
        }

        if (localPort > 0) {
            return local;   // have a specific local address
        }

        // Missing the port from local address
        return new SshdSocketAddress(localName, boundPort);
    }

    public static LocalForwardingEntry findMatchingEntry(
            String host, int port, Collection<? extends LocalForwardingEntry> entries) {
        return findMatchingEntry(host, SshdSocketAddress.isWildcardAddress(host), port, entries);
    }

    /**
     * @param  host            The host - ignored if {@code null}/empty and not wildcard address match - i.e., no match
     *                         reported
     * @param  anyLocalAddress Is host the wildcard address - in which case, we try an exact match first for the host,
     *                         and if that fails then only the port is matched
     * @param  port            The port - ignored if non-positive - i.e., no match reported
     * @param  entries         The {@link Collection} of {@link LocalForwardingEntry} to check - ignored if
     *                         {@code null}/empty - i.e., no match reported
     * @return                 The <U>first</U> entry whose local or bound address matches the host name - case
     *                         <U>insensitive</U> <B>and</B> has a matching bound port - {@code null} if no match found
     */
    public static LocalForwardingEntry findMatchingEntry(
            String host, boolean anyLocalAddress, int port, Collection<? extends LocalForwardingEntry> entries) {
        if ((port <= 0) || (GenericUtils.isEmpty(entries))) {
            return null;
        }

        if (GenericUtils.isEmpty(host) && (!anyLocalAddress)) {
            return null;
        }

        LocalForwardingEntry candidate = null;
        for (LocalForwardingEntry e : entries) {
            SshdSocketAddress bound = e.getBoundAddress();
            /*
             * Note we don't check the local port since it could be zero.
             * If it isn't then it must be equal to the bound port (enforced in constructor)
             */
            if (port != bound.getPort()) {
                continue;
            }

            /*
             * We first try an exact match - if not found, declare this
             * a candidate and return it if host is any local address
             */

            String boundName = bound.getHostName();
            if (SshdSocketAddress.isEquivalentHostName(host, boundName, false)) {
                return e;
            }

            SshdSocketAddress local = e.getLocalAddress();
            String localName = local.getHostName();
            if (SshdSocketAddress.isEquivalentHostName(host, localName, false)) {
                return e;
            }

            if (SshdSocketAddress.isLoopbackAlias(host, boundName)
                    || SshdSocketAddress.isLoopbackAlias(host, localName)) {
                return e;
            }

            if (anyLocalAddress) {
                if (candidate != null) {
                    throw new IllegalStateException(
                            "Multiple candidate matches for " + host + "@" + port + ": " + candidate + ", " + e);
                }
                candidate = e;
            }
        }

        if (anyLocalAddress) {
            return candidate;
        }

        return null; // no match found
    }
}
