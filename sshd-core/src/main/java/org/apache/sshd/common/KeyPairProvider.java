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

import java.security.KeyPair;

/**
 * Provider for key pairs.  This provider is used on the server side to provide
 * the host key, or on the client side to provide the user key.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface KeyPairProvider {

    /**
     * SSH identifier for RSA keys
     */
    String SSH_RSA = "ssh-rsa";

    /**
     * SSH identifier for DSA keys
     */
    String SSH_DSS = "ssh-dss";

    /**
     * Load a key of the specified type which can be "ssh-rsa" or "ssh-dss".
     * If there is no key of this type, return <code>null</code>
     *
     * @param type the type of key to load
     * @return a valid key pair or <code>null</code>
     */
    KeyPair loadKey(String type);

    /**
     * Return a comma separated list of the key types available
     *
     * @return the list of key availables
     */
    String getKeyTypes();
}
