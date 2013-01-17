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
package org.apache.sshd.common;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

/**
 * A simple socket address holding the host name and port number.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshdSocketAddress extends SocketAddress {

    private final String hostName;
    private final int port;

    public SshdSocketAddress(String hostName, int port) {
        if (hostName == null) {
            throw new IllegalArgumentException("HostName can not be null");
        }
        if (port < 0) {
            throw new IllegalArgumentException("Port must be >= 0");
        }
        this.hostName = hostName;
        this.port = port;
    }

    public String getHostName() {
        return hostName;
    }

    public int getPort() {
        return port;
    }

    public InetSocketAddress toInetSocketAddress() {
        return new InetSocketAddress(hostName.length() == 0 ? "0.0.0.0" : hostName, port);
    }

    @Override
    public String toString() {
        return hostName + ":" + port;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SshdSocketAddress that = (SshdSocketAddress) o;
        if (port != that.port) return false;
        if (!hostName.equals(that.hostName)) return false;
        return true;
    }

    @Override
    public int hashCode() {
        int result = hostName.hashCode();
        result = 31 * result + port;
        return result;
    }
}
