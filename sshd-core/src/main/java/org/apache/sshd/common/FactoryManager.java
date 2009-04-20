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

import java.util.List;
import java.util.Map;

/**
 * This interface allows retrieving all the <code>NamedFactory</code> used
 * in the SSH protocol.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public interface FactoryManager {

    /**
     * Key used to retrieve the value of the window size in the
     * configuration properties map.
     */
    public static final String WINDOW_SIZE = "window-size";

    /**
     * Key used to retrieve the value of the maximum packet size
     * in the configuration properties map.
     */
    public static final String MAX_PACKET_SIZE = "packet-size";

    /**
     * Key used to retrieve the value in the configuration properties map
     * of the maximum number of failed authentication requests before the
     * server closes the connection.
     */
    public static final String MAX_AUTH_REQUESTS = "max-auth-requests";

    /**
     * Key used to retrieve the value of the timeout after which
     * the server will close the connection if the client has not been
     * authenticated.
     */
    public static final String AUTH_TIMEOUT = "auth-timeout";

    /**
     * A map of properties that can be used to configure the SSH server
     * or client.  This map will never be changed by either the server or
     * client and is not supposed to be changed at runtime (changes are not
     * bound to have any effect on a running client or server), though it may
     * affect the creation of sessions later as these values are usually not
     * cached.
     *
     * @return a valid <code>Map</code> containing configuration values, never <code>null</code>
     */
    Map<String,String> getProperties();

    /**
     * An upper case string identifying the version of the
     * software used on client or server side.
     * This version includes the name of the software and usually
     * looks like: <code>SSHD-1.0</code>
     *
     * @return the version of the software
     */
    String getVersion();

    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     *
     * @return a list of named <code>KeyExchange</code> factories, never <code>null</code>
     */
    List<NamedFactory<KeyExchange>> getKeyExchangeFactories();

    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     *
     * @return a list of named <code>Cipher</code> factories, never <code>null</code>
     */
    List<NamedFactory<Cipher>> getCipherFactories();

    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     *
     * @return a list of named <code>Compression</code> factories, never <code>null</code>
     */
    List<NamedFactory<Compression>> getCompressionFactories();

    /**
     * Retrieve the list of named factories for <code>Mac</code>.
     *
     * @return a list of named <code>Mac</code> factories, never <code>null</code>
     */
    List<NamedFactory<Mac>> getMacFactories();

    /**
     * Retrieve the list of named factories for <code>Signature</code>.
     *
     * @return a list of named <code>Signature</code> factories, never <code>null</code>
     */
    List<NamedFactory<Signature>> getSignatureFactories();

    /**
     * Retrieve the <code>KeyPairProvider</code> that will be used to find
     * the host key to use on the server side or the user key on the client side.
     *
     * @return the <code>KeyPairProvider</code>, never <code>null</code>
     */
    KeyPairProvider getKeyPairProvider();

    /**
     * Retrieve the <code>Random</code> factory to be used.
     *
     * @return the <code>Random</code> factory, never <code>null</code>
     */
    NamedFactory<Random> getRandomFactory();

}
