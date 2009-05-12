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

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SecurityUtils {

    public static final String BOUNCY_CASTLE = "BC";

    private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);

    private static String securityProvider = null;
    private static Boolean registerBouncyCastle;
    private static boolean registrationDone;

    public static synchronized void setSecurityProvider(String securityProvider) {
        SecurityUtils.securityProvider = securityProvider;
        registrationDone = false;
    }

    public static synchronized void setRegisterBouncyCastle(boolean registerBouncyCastle) {
        SecurityUtils.registerBouncyCastle = registerBouncyCastle;
        registrationDone = false;
    }

    public static synchronized String getSecurityProvider() {
        register();
        return securityProvider;
    }

    public static synchronized boolean isBouncyCastleRegistered() {
        register();
        return BOUNCY_CASTLE.equals(securityProvider);
    }

    private static void register() {
        if (!registrationDone) {
            if (securityProvider == null && (registerBouncyCastle == null || registerBouncyCastle)) {
                // Use an inner class to avoid a strong dependency from SshServer on BouncyCastle
                try {
                    new BouncyCastleRegistration().run();
                } catch (Throwable t) {
                    if (registerBouncyCastle == null) {
                        LOG.info("BouncyCastle not registered, using the default JCE provider");
                    } else {
                        LOG.error("Failed to register BouncyCastle as the defaut JCE provider");
                        throw new RuntimeException("Failed to register BouncyCastle as the defaut JCE provider", t);
                    }
                }
            }
            registrationDone = true;
        }
    }

    private static class BouncyCastleRegistration {
        public void run() throws Exception {
            if (java.security.Security.getProvider(BOUNCY_CASTLE) == null) {
                LOG.info("Trying to register BouncyCastle as a JCE provider");
                java.security.Security.addProvider(new BouncyCastleProvider());
                MessageDigest.getInstance("MD5", BOUNCY_CASTLE);
                KeyAgreement.getInstance("DH", BOUNCY_CASTLE);
                LOG.info("Registration succeeded");
            } else {
                LOG.info("BouncyCastle already registered as a JCE provider");
            }
            securityProvider = BOUNCY_CASTLE;
        }
    }

    public static synchronized KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return KeyFactory.getInstance(algorithm);
        } else {
            return KeyFactory.getInstance(algorithm, getSecurityProvider());
        }
    }

    public static synchronized Cipher getCipher(String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return Cipher.getInstance(transformation);
        } else {
            return Cipher.getInstance(transformation, getSecurityProvider());
        }
    }

    public static synchronized MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return MessageDigest.getInstance(algorithm);
        } else {
            return MessageDigest.getInstance(algorithm, getSecurityProvider());
        }
    }

    public static synchronized KeyPairGenerator getKeyPairGenerator(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return KeyPairGenerator.getInstance(algorithm);
        } else {
            return KeyPairGenerator.getInstance(algorithm, getSecurityProvider());
        }
    }

    public static synchronized KeyAgreement getKeyAgreement(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return KeyAgreement.getInstance(algorithm);
        } else {
            return KeyAgreement.getInstance(algorithm, getSecurityProvider());
        }
    }

    public static synchronized Mac getMac(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return Mac.getInstance(algorithm);
        } else {
            return Mac.getInstance(algorithm, getSecurityProvider());
        }
    }

    public static synchronized Signature getSignature(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        register();
        if (getSecurityProvider() == null) {
            return Signature.getInstance(algorithm);
        } else {
            return Signature.getInstance(algorithm, getSecurityProvider());
        }
    }

}
