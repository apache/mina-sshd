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
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public interface FactoryManager {

    public static final String WINDOW_SIZE = "window-size";
    public static final String MAX_PACKET_SIZE = "packet-size";
    public static final String MAX_AUTH_REQUESTS = "max-auth-requests";
    public static final String AUTH_TIMEOUT = "auth-timeout";

    Map<String,String> getProperties();

    String getVersion();

    List<NamedFactory<KeyExchange>> getKeyExchangeFactories();

    List<NamedFactory<Cipher>> getCipherFactories();

    List<NamedFactory<Compression>> getCompressionFactories();

    List<NamedFactory<Mac>> getMacFactories();

    List<NamedFactory<Signature>> getSignatureFactories();

    KeyPairProvider getKeyPairProvider();

    NamedFactory<Random> getRandomFactory();

}
