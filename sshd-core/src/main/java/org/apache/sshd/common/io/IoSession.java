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
package org.apache.sshd.common.io;

import java.net.SocketAddress;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.util.net.ConnectionEndpointsIndicator;

public interface IoSession extends ConnectionEndpointsIndicator, PacketWriter, Closeable {

    /**
     * @return a unique identifier for this session. Every session has its own
     * ID which is different from any other.
     */
    long getId();

    /**
     * @return The service address through which this session was accepted - {@code null}
     * if session was initiated by this peer instead of being accepted
     */
    SocketAddress getAcceptanceAddress();

    /**
     * Returns the value of the user-defined attribute of this session.
     *
     * @param key the key of the attribute
     * @return {@code null} if there is no attribute with the specified key
     */
    Object getAttribute(Object key);

    /**
     * Sets a user-defined attribute.
     *
     * @param key   the key of the attribute
     * @param value the value of the attribute
     * @return The old value of the attribute - {@code null} if it is new.
     */
    Object setAttribute(Object key, Object value);

    /**
     * Sets a user defined attribute if the attribute with the specified key
     * is not set yet. This method is same with the following code except
     * that the operation is performed atomically.
     * <pre><code>
     * if (containsAttribute(key)) {
     *     return getAttribute(key);
     * } else {
     *     return setAttribute(key, value);
     * }
     * </code></pre>
     *
     * @param key The key of the attribute we want to set
     * @param value The value we want to set
     * @return The old value of the attribute - {@code null} if not found.
     */
    Object setAttributeIfAbsent(Object key, Object value);

    /**
     * Removes a user-defined attribute with the specified key.
     *
     * @param key The key of the attribute we want to remove
     * @return The old value of the attribute - {@code null} if not found.
     */
    Object removeAttribute(Object key);

    /**
     * @return the {@link IoService} that created this session.
     */
    IoService getService();
}
