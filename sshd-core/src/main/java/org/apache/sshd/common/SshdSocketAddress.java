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
package org.apache.sshd.common;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * <P>A simple socket address holding the host name and port number. The reason
 * it does not extend {@link InetSocketAddress} is twofold:</P>
 * <OL>
 * <LI><P>
 * The {@link InetSocketAddress} performs a DNS resolution on the
 * provided host name - which we don't want do use until we want to
 * create a connection using this address (thus the {@link #toInetSocketAddress()}
 * call which executes this query
 * </P></LI>
 *
 * <LI><P>
 * If empty host name is provided we replace it with the <I>any</I>
 * address of 0.0.0.0
 * </P></LI>
 * </OL>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshdSocketAddress extends SocketAddress {

    /**
     * A dummy placeholder that can be used instead of {@code null}s
     */
    public static final SshdSocketAddress LOCALHOST_ADDRESS = new SshdSocketAddress("localhost", 0);

    private static final long serialVersionUID = 6461645947151952729L;

    private final String hostName;
    private final int port;

    public SshdSocketAddress(String hostName, int port) {
        ValidateUtils.checkNotNull(hostName, "Host name may not be null");
        this.hostName = GenericUtils.isEmpty(hostName) ? "0.0.0.0" : hostName;

        ValidateUtils.checkTrue(port >= 0, "Port must be >= 0", Integer.valueOf(port));
        this.port = port;
    }

    public String getHostName() {
        return hostName;
    }

    public int getPort() {
        return port;
    }

    public InetSocketAddress toInetSocketAddress() {
        return new InetSocketAddress(getHostName(), getPort());
    }

    @Override
    public String toString() {
        return getHostName() + ":" + getPort();
    }

    protected boolean isEquivalent(SshdSocketAddress that) {
        if (that == null) {
            return false;
        } else if (that == this) {
            return true;
        } else {
            return (this.getPort() == that.getPort())
                    && Objects.equals(this.getHostName(), that.getHostName());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (getClass() != o.getClass()) {
            return false;
        }
        return isEquivalent((SshdSocketAddress) o);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getHostName()) + getPort();
    }
}
