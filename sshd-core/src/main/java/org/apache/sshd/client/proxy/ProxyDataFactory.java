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
package org.apache.sshd.client.proxy;

import java.net.InetSocketAddress;

/**
 * A factory for obtaining {@link ProxyData} to connect through some proxy.
 */
@FunctionalInterface
public interface ProxyDataFactory {

    /**
     * Get the {@link ProxyData} to connect to a proxy. It should return a <em>new</em> {@link ProxyData} instance every
     * time. The caller is responsible for clearing the password, if any, once it is no longer needed.
     *
     * @param  remoteAddress to connect to
     * @return               the {@link ProxyData} or {@code null} if a direct connection is to be made
     */
    ProxyData get(InetSocketAddress remoteAddress);
}
