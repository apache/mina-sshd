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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.SecurityUtils;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>This host key provider loads private keys from the specified resources.</p>
 *
 * <p>Note that this class has a direct dependency on BouncyCastle and won't work
 * unless it has been correctly registered as a security provider.</p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ResourceKeyPairProvider extends AbstractKeyPairProvider {
    // --- Shared ---

    /**
     * Logger
     */
    private final Logger log = LoggerFactory.getLogger(getClass());

    // --- Properties ---

    /**
     * Class loader
     */
    private final ClassLoader cloader;

    /**
     * Key resources
     */
    private String[] resources;

    /**
     * Password finder
     */
    private PasswordFinder passwordFinder;

    // ---

    /**
     * No-arg constructor.
     */
    public ResourceKeyPairProvider() {
        this.cloader = this.getClass().getClassLoader();
    } // end of <init>

    /**
     * Bulk constructor 1.
     */
    public ResourceKeyPairProvider(String[] resources) {
        this.cloader = this.getClass().getClassLoader();
        this.resources = resources;
    } // end of <init>

    /**
     * Bulk constructor 2.
     */
    public ResourceKeyPairProvider(String[] resources,
                                   PasswordFinder passwordFinder) {

        this.cloader = this.getClass().getClassLoader();
        this.resources = resources;
        this.passwordFinder = passwordFinder;
    } // end of <init>

    /**
     * Bulk constructor 3.
     */
    public ResourceKeyPairProvider(String[] resources,
                                   PasswordFinder passwordFinder,
                                   ClassLoader cloader) {

        this.cloader = cloader;
        this.resources = resources;
        this.passwordFinder = passwordFinder;
    } // end of <init>

    // --- Properties accessors ---

    /**
     * {@inheritDoc}
     */
    public String[] getResources() {
        return this.resources;
    } // end of getResources

    /**
     * {@inheritDoc}
     */
    public void setResources(String[] resources) {
        this.resources = resources;
    } // end of setResources

    /**
     * {@inheritDoc}
     */
    public PasswordFinder getPasswordFinder() {
        return this.passwordFinder;
    } // end of getPasswordFinder

    /**
     * {@inheritDoc}
     */
    public void setPasswordFinder(PasswordFinder passwordFinder) {
        this.passwordFinder = passwordFinder;
    } // end of setPasswordFinder

    /**
     * {@inheritDoc}
     */
    public Iterable<KeyPair> loadKeys() {
        if (!SecurityUtils.isBouncyCastleRegistered()) {
            throw new IllegalStateException("BouncyCastle must be registered as a JCE provider");
        } // end of if
        return new Iterable<KeyPair>() {
            public Iterator<KeyPair> iterator() {
                return new Iterator<KeyPair>() {
                    private final Iterator<String> iterator = Arrays.asList(resources).iterator();
                    private KeyPair nextKeyPair;
                    private boolean nextKeyPairSet = false;
                    public boolean hasNext() {
                        return nextKeyPairSet || setNextObject();
                    }
                    public KeyPair next() {
                        if (!nextKeyPairSet) {
                            if (!setNextObject()) {
                                throw new NoSuchElementException();
                            }
                        }
                        nextKeyPairSet = false;
                        return nextKeyPair;
                    }
                    public void remove() {
                        throw new UnsupportedOperationException();
                    }
                    private boolean setNextObject() {
                        while (iterator.hasNext()) {
                            String file = iterator.next();
                            nextKeyPair = doLoadKey(file);
                            if (nextKeyPair != null) {
                                nextKeyPairSet = true;
                                return true;
                            }
                        }
                        return false;
                    }

                };
            }
        };
    }

    protected KeyPair doLoadKey(String resource) {
        PEMParser r = null;
        InputStreamReader isr = null;
        InputStream is = null;
        try {
            is = this.cloader.getResourceAsStream(resource);
            isr = new InputStreamReader(is);
            r = new PEMParser(isr);

            Object o = r.readObject();

            JcaPEMKeyConverter pemConverter = new JcaPEMKeyConverter();
            pemConverter.setProvider("BC");
            if (passwordFinder != null && o instanceof PEMEncryptedKeyPair) {
                JcePEMDecryptorProviderBuilder decryptorBuilder = new JcePEMDecryptorProviderBuilder();
                PEMDecryptorProvider pemDecryptor = decryptorBuilder.build(passwordFinder.getPassword());
                o = pemConverter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(pemDecryptor));
            }

            if (o instanceof PEMKeyPair) {
                o = pemConverter.getKeyPair((PEMKeyPair)o);
                return (KeyPair) o;
            } else if (o instanceof KeyPair) {
                return (KeyPair) o;
            } // end of if
        } catch (Exception e) {
            log.warn("Unable to read key " + resource, e);
        } finally {
            IoUtils.closeQuietly(r, is, isr);
        } // end of finally
        return null;
    } // end of doLoadKey

} // end of class ResourceKeyPairProvider
