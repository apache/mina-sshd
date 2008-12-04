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
package org.apache.sshd.common.keyprovider;

import java.security.KeyPair;
import java.security.interfaces.DSAKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.KeyPairProvider;

public abstract class AbstractKeyPairProvider implements KeyPairProvider {

    public KeyPair loadKey(String type) {
        assert type != null;
        KeyPair[] keys = loadKeys();
        for (KeyPair key : keys) {
            if (type.equals(getKeyType(key))) {
                return key;
            }
        }
        return null;
    }

    public String getKeyTypes() {
        List<String> types = new ArrayList<String>();
        KeyPair[] keys = loadKeys();
        for (KeyPair key : keys) {
            String type = getKeyType(key);
            if (type != null && !types.contains(type)) {
                types.add(type);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (String type : types) {
            if (sb.length() > 0) {
                sb.append(",");
            }
            sb.append(type);
        }
        return sb.toString();
    }

    protected String getKeyType(KeyPair kp) {
        Object key = kp.getPrivate() != null ? kp.getPrivate() : kp.getPublic();
        if (key instanceof DSAKey) {
            return SSH_DSS;
        } else if (key instanceof RSAKey) {
            return SSH_RSA;
        }
        return null;
    }

    protected abstract KeyPair[] loadKeys();
}
