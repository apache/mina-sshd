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

import java.io.IOException;

import org.apache.mina.core.future.WriteFuture;
import org.apache.sshd.common.util.Buffer;

/**
 * Represents an SSH session
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Session {

    /**
     * Returns the value of the user-defined attribute of this session.
     *
     * @param key the key of the attribute; must not be null.
     * @return <tt>null</tt> if there is no attribute with the specified key
     */
    <T> T getAttribute(AttributeKey<T> key);

    /**
     * Sets a user-defined attribute.
     *
     * @param key   the key of the attribute; must not be null.
     * @param value the value of the attribute; must not be null.
     * @return The old value of the attribute.  <tt>null</tt> if it is new.
     */
    <T, E extends T> T setAttribute(AttributeKey<T> key, E value);

    /**
     * Retrieve the name of the user authenticated on this session
     * or null if the session has not been authenticated yet.
     *
     * @return the user name.
     */
    String getUsername();

    /**
     * Retrieve the FactoryManager that has created this session
     *
     * @return the factory manager, can not be <tt>null</tt>.
     */
    FactoryManager getFactoryManager();

    /**
     * Retrieve a configuration property as an integer
     *
     * @param name the name of the property
     * @param defaultValue the default value
     * @return the value of the configuration property or the default value if not found
     */
    int getIntProperty(String name, int defaultValue);

    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space
     * (5 bytes) for the packet header.
     *
     * @param cmd the SSH command
     * @param estimatedSize estimated number of bytes the buffer will hold, 0 if unknown.
     * @return a new buffer ready for write
     */
    Buffer createBuffer(SshConstants.Message cmd, int estimatedSize);

    /**
     * Encode and send the given buffer.
     * The buffer has to have 5 bytes free at the beginning to allow the encoding to take place.
     * Also, the write position of the buffer has to be set to the position of the last byte to write.
     *
     * @param buffer the buffer to encode and send
     * @return a future that can be used to check when the packet has actually been sent
     * @throws java.io.IOException if an error occured when encoding sending the packet
     */
    WriteFuture writePacket(Buffer buffer) throws IOException;

    /**
     * Handle any exceptions that occured on this session.
     * The session will be closed and a disconnect packet will be
     * sent before if the given exception is an
     * {@link org.apache.sshd.common.SshException}.
     *
     * @param t the exception to process
     * @throws IOException
     */
    void exceptionCaught(Throwable t);

    /**
     * Register a newly created channel with a new unique identifier
     *
     * @param channel the channel to register
     * @return the id of this channel
     * @throws Exception
     */
    int registerChannel(Channel channel) throws Exception;

    /**
     * Remove this channel from the list of managed channels
     *
     * @param channel the channel
     */
    void unregisterChannel(Channel channel);

    /**
     * Add a session |listener|.
     *
     * @param listener the session listener to add
     */
    void addListener(SessionListener listener);

    /**
     * Remove a session |listener|.
     *
     * @param listener the session listener to remove
     */
    void removeListener(SessionListener listener);

    /**
     * Type safe key for storage within the user attributes of {@link org.apache.sshd.common.session.AbstractSession}.
     * Typically it is used as a static variable that is shared between the producer
     * and the consumer. To further restrict access the setting or getting it from
     * the Session you can add static get and set methods, e.g:
     *
     * private static final AttributeKey<MyValue> MY_KEY = new AttributeKey<MyValue>();
     *
     * public static MyValue getMyValue(Session s) {
     *   return s.getAttribute(MY_KEY);
     * }
     *
     * private void setMyValue(Session s, MyValue value) {
     *   s.setAttribute(MY_KEY, value);
     * }
     *
     * @param T type of value stored in the attribute.
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public class AttributeKey<T> {
    }

}
