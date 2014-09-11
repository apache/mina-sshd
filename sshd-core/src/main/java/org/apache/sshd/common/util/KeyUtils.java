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
package org.apache.sshd.common.util;

import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;

import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.digest.MD5;

/**
 * Utility class for keys
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class KeyUtils {

    /**
     * Retrieve the public key fingerprint
     *
     * @param key the public key
     * @return the fingerprint
     */
    public static String getFingerPrint(PublicKey key) {
        try {
            Buffer buffer = new Buffer();
            buffer.putRawPublicKey(key);
            MD5 md5 = new MD5();
            md5.init();
            md5.update(buffer.array(), 0, buffer.wpos());
            byte[] data = md5.digest();
            return BufferUtils.printHex(data, 0, data.length, ':');
        } catch (Exception e) {
            return "Unable to compute fingerprint";
        }
    }

    /**
     * Retrieve the key type
     *
     * @param kp a key pair
     * @return the key type
     */
    public static String getKeyType(KeyPair kp) {
        return getKeyType(kp.getPrivate() != null ? kp.getPrivate() : kp.getPublic());
    }

    /**
     * Retrieve the key type
     *
     * @param key a public or private key
     * @return the key type
     */
    public static String getKeyType(Key key) {
        if (key instanceof DSAKey) {
            return KeyPairProvider.SSH_DSS;
        } else if (key instanceof RSAKey) {
            return KeyPairProvider.SSH_RSA;
        } else if (key instanceof ECKey) {
            ECKey ecKey = (ECKey) key;
            ECParameterSpec ecSpec = ecKey.getParams();
            return ECCurves.ECDSA_SHA2_PREFIX + ECCurves.getCurveName(ecSpec);
        }
        return null;
    }

    private KeyUtils() {
    }

}
