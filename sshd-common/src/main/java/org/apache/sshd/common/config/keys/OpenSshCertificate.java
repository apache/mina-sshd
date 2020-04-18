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
package org.apache.sshd.common.config.keys;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;

public interface OpenSshCertificate extends PublicKey, PrivateKey {
    int SSH_CERT_TYPE_USER = 1;
    int SSH_CERT_TYPE_HOST = 2;

    String getRawKeyType();

    byte[] getNonce();

    String getKeyType();

    PublicKey getServerHostKey();

    long getSerial();

    int getType();

    String getId();

    Collection<String> getPrincipals();

    long getValidAfter();

    long getValidBefore();

    List<String> getCriticalOptions();

    List<String> getExtensions();

    String getReserved();

    PublicKey getCaPubKey();

    byte[] getMessage();

    byte[] getSignature();

    String getSignatureAlg();
}
