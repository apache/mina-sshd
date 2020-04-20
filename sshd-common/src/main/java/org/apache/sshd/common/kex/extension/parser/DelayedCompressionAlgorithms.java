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

package org.apache.sshd.common.kex.extension.parser;

import java.util.List;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/rfc8308#section-3.2">RFC-8308 - section 3.2</A>
 */
public class DelayedCompressionAlgorithms {
    private List<String> client2server;
    private List<String> server2client;

    public DelayedCompressionAlgorithms() {
        super();
    }

    public List<String> getClient2Server() {
        return client2server;
    }

    public DelayedCompressionAlgorithms withClient2Server(List<String> client2server) {
        setClient2Server(client2server);
        return this;
    }

    public void setClient2Server(List<String> client2server) {
        this.client2server = client2server;
    }

    public List<String> getServer2Client() {
        return server2client;
    }

    public DelayedCompressionAlgorithms withServer2Client(List<String> server2client) {
        setServer2Client(server2client);
        return this;
    }

    public void setServer2Client(List<String> server2client) {
        this.server2client = server2client;
    }

    @Override
    public int hashCode() {
        // Order might differ
        return 31 * GenericUtils.size(getClient2Server())
               + 37 * GenericUtils.size(getServer2Client());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        DelayedCompressionAlgorithms other = (DelayedCompressionAlgorithms) obj;
        return (GenericUtils.findFirstDifferentValueIndex(getClient2Server(), other.getClient2Server()) < 0)
                && (GenericUtils.findFirstDifferentValueIndex(getServer2Client(), other.getServer2Client()) < 0);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[client2server=" + getClient2Server()
               + ", server2client=" + getServer2Client()
               + "]";
    }
}
