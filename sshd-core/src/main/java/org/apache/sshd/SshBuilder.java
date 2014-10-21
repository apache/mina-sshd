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
package org.apache.sshd;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.sshd.client.ServerKeyVerifier;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.common.AbstractFactoryManager;
import org.apache.sshd.common.Channel;
import org.apache.sshd.common.Cipher;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Random;
import org.apache.sshd.common.RequestHandler;
import org.apache.sshd.common.Signature;
import org.apache.sshd.common.TcpipForwarderFactory;
import org.apache.sshd.common.cipher.AES128CBC;
import org.apache.sshd.common.cipher.AES128CTR;
import org.apache.sshd.common.cipher.AES192CBC;
import org.apache.sshd.common.cipher.AES192CTR;
import org.apache.sshd.common.cipher.AES256CBC;
import org.apache.sshd.common.cipher.AES256CTR;
import org.apache.sshd.common.cipher.ARCFOUR128;
import org.apache.sshd.common.cipher.ARCFOUR256;
import org.apache.sshd.common.cipher.BlowfishCBC;
import org.apache.sshd.common.cipher.TripleDESCBC;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.forward.DefaultTcpipForwarderFactory;
import org.apache.sshd.common.forward.TcpipServerChannel;
import org.apache.sshd.common.mac.HMACMD5;
import org.apache.sshd.common.mac.HMACMD596;
import org.apache.sshd.common.mac.HMACSHA1;
import org.apache.sshd.common.mac.HMACSHA196;
import org.apache.sshd.common.mac.HMACSHA256;
import org.apache.sshd.common.mac.HMACSHA512;
import org.apache.sshd.common.random.BouncyCastleRandom;
import org.apache.sshd.common.random.JceRandom;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.signature.SignatureDSA;
import org.apache.sshd.common.signature.SignatureECDSA;
import org.apache.sshd.common.signature.SignatureRSA;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.global.CancelTcpipForwardHandler;
import org.apache.sshd.server.global.KeepAliveHandler;
import org.apache.sshd.server.global.NoMoreSessionsHandler;
import org.apache.sshd.server.global.TcpipForwardHandler;

/**
 * A builder object for creating SshServer instances.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SshBuilder {

    public static ClientBuilder client() {
        return new ClientBuilder();
    }

    public static ServerBuilder server() {
        return new ServerBuilder();
    }

    protected static class BaseBuilder<T extends AbstractFactoryManager, S extends BaseBuilder<T, S>> {

        protected Factory<T> factory = null;

        protected List<NamedFactory<KeyExchange>> keyExchangeFactories = null;
        protected List<NamedFactory<Cipher>> cipherFactories = null;
        protected List<NamedFactory<Compression>> compressionFactories = null;
        protected List<NamedFactory<Mac>> macFactories = null;
        protected List<NamedFactory<Signature>> signatureFactories = null;
        protected Factory<Random> randomFactory = null;
        protected List<NamedFactory<Channel>> channelFactories = null;
        protected FileSystemFactory fileSystemFactory = null;
        protected TcpipForwarderFactory tcpipForwarderFactory = null;
        protected List<RequestHandler<ConnectionService>> globalRequestHandlers = null;

        protected S fillWithDefaultValues() {
            if (SecurityUtils.isBouncyCastleRegistered()) {
                if (signatureFactories == null) {
                    signatureFactories = Arrays.asList(
                            new SignatureECDSA.NISTP256Factory(),
                            new SignatureECDSA.NISTP384Factory(),
                            new SignatureECDSA.NISTP521Factory(),
                            new SignatureDSA.Factory(),
                            new SignatureRSA.Factory());
                }
                if (randomFactory == null) {
                    randomFactory = new SingletonRandomFactory(new BouncyCastleRandom.Factory());
                }
                // EC keys are not supported until OpenJDK 7
            } else if (SecurityUtils.hasEcc()) {
                if (signatureFactories == null) {
                    signatureFactories = Arrays.asList(
                            new SignatureECDSA.NISTP256Factory(),
                            new SignatureECDSA.NISTP384Factory(),
                            new SignatureECDSA.NISTP521Factory(),
                            new SignatureDSA.Factory(),
                            new SignatureRSA.Factory());
                }
                if (randomFactory == null) {
                    randomFactory = new SingletonRandomFactory(new JceRandom.Factory());
                }
            } else {
                if (signatureFactories == null) {
                    signatureFactories = Arrays.asList(
                            new SignatureDSA.Factory(),
                            new SignatureRSA.Factory());
                }
                if (randomFactory == null) {
                    randomFactory = new SingletonRandomFactory(new JceRandom.Factory());
                }
            }

            if (cipherFactories == null) {
                cipherFactories = setUpDefaultCiphers();
            }

            // Compression is not enabled by default
            //if (compressionFactories == null) {
            //    compressionFactories = Arrays.<NamedFactory<Compression>>asList(
            //            new CompressionNone.Factory(),
            //            new CompressionZlib.Factory(),
            //            new CompressionDelayedZlib.Factory());
            //}
            if (compressionFactories == null) {
                compressionFactories = Arrays.<NamedFactory<Compression>>asList(
                        new CompressionNone.Factory());
            }
            if (macFactories == null) {
                macFactories = Arrays.asList(
                        new HMACSHA256.Factory(),
                        new HMACSHA512.Factory(),
                        new HMACSHA1.Factory(),
                        new HMACMD5.Factory(),
                        new HMACSHA196.Factory(),
                        new HMACMD596.Factory());
            }
            if (fileSystemFactory == null) {
                fileSystemFactory = new NativeFileSystemFactory();
            }
            if (tcpipForwarderFactory == null) {
                tcpipForwarderFactory = new DefaultTcpipForwarderFactory();
            }

            return me();
        }

        public S keyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories) {
            this.keyExchangeFactories = keyExchangeFactories;
            return me();
        }

        public S signatureFactories(final List<NamedFactory<Signature>> signatureFactories) {
            this.signatureFactories = signatureFactories;
            return me();
        }

        public S randomFactory(final Factory<Random> randomFactory) {
            this.randomFactory = randomFactory;
            return me();
        }

        public S cipherFactories(final List<NamedFactory<Cipher>> cipherFactories) {
            this.cipherFactories = cipherFactories;
            return me();
        }

        public S compressionFactories(final List<NamedFactory<Compression>> compressionFactories) {
            this.compressionFactories = compressionFactories;
            return me();
        }

        public S macFactories(final List<NamedFactory<Mac>> macFactories) {
            this.macFactories = macFactories;
            return me();
        }

        public S channelFactories(final List<NamedFactory<Channel>> channelFactories) {
            this.channelFactories = channelFactories;
            return me();
        }

        public S fileSystemFactory(final FileSystemFactory fileSystemFactory) {
            this.fileSystemFactory = fileSystemFactory;
            return me();
        }

        public S tcpipForwarderFactory(final TcpipForwarderFactory tcpipForwarderFactory) {
            this.tcpipForwarderFactory = tcpipForwarderFactory;
            return me();
        }

        public S globalRequestHandlers(final List<RequestHandler<ConnectionService>> globalRequestHandlers) {
            this.globalRequestHandlers = globalRequestHandlers;
            return me();
        }

        public S factory(final Factory<T> factory) {
            this.factory = factory;
            return me();
        }

        public T build(final boolean isFillWithDefaultValues) {
            if (isFillWithDefaultValues) {
                fillWithDefaultValues();
            }

            T ssh = factory.create();

            ssh.setKeyExchangeFactories(keyExchangeFactories);
            ssh.setSignatureFactories(signatureFactories);
            ssh.setRandomFactory(randomFactory);
            ssh.setCipherFactories(cipherFactories);
            ssh.setCompressionFactories(compressionFactories);
            ssh.setMacFactories(macFactories);
            ssh.setChannelFactories(channelFactories);
            ssh.setFileSystemFactory(fileSystemFactory);
            ssh.setTcpipForwarderFactory(tcpipForwarderFactory);
            ssh.setGlobalRequestHandlers(globalRequestHandlers);

            return ssh;
        }

        public T build() {
            return build(true);
        }

        @SuppressWarnings("unchecked")
        protected S me() {
            return (S) this;
        }

        protected static List<NamedFactory<Cipher>> setUpDefaultCiphers() {
            List<NamedFactory<Cipher>> avail = new LinkedList<NamedFactory<Cipher>>();
            avail.add(new AES128CTR.Factory());
            avail.add(new AES192CTR.Factory());
            avail.add(new AES256CTR.Factory());
            avail.add(new ARCFOUR128.Factory());
            avail.add(new ARCFOUR256.Factory());
            avail.add(new AES128CBC.Factory());
            avail.add(new TripleDESCBC.Factory());
            avail.add(new BlowfishCBC.Factory());
            avail.add(new AES192CBC.Factory());
            avail.add(new AES256CBC.Factory());

            for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext(); ) {
                final NamedFactory<Cipher> f = i.next();
                try {
                    final Cipher c = f.create();
                    final byte[] key = new byte[c.getBlockSize()];
                    final byte[] iv = new byte[c.getIVSize()];
                    c.init(Cipher.Mode.Encrypt, key, iv);
                } catch (InvalidKeyException e) {
                    i.remove();
                } catch (Exception e) {
                    i.remove();
                }
            }
            return avail;
        }
    }

    /**
     * SshClient builder
     */
    public static class ClientBuilder extends BaseBuilder<SshClient, ClientBuilder> {

        protected ServerKeyVerifier serverKeyVerifier;

        public ClientBuilder serverKeyVerifier(ServerKeyVerifier serverKeyVerifier) {
            this.serverKeyVerifier = serverKeyVerifier;
            return me();
        }

        @Override
        protected ClientBuilder fillWithDefaultValues() {
            super.fillWithDefaultValues();
            if (SecurityUtils.isBouncyCastleRegistered()) {
                if (keyExchangeFactories == null) {
                    keyExchangeFactories = Arrays.asList(
                            new org.apache.sshd.client.kex.DHGEX256.Factory(),
                            new org.apache.sshd.client.kex.DHGEX.Factory(),
                            new org.apache.sshd.client.kex.ECDHP256.Factory(),
                            new org.apache.sshd.client.kex.ECDHP384.Factory(),
                            new org.apache.sshd.client.kex.ECDHP521.Factory(),
                            new org.apache.sshd.client.kex.DHG14.Factory(),
                            new org.apache.sshd.client.kex.DHG1.Factory());
                }
            // EC keys are not supported until OpenJDK 7
            } else if (SecurityUtils.hasEcc()) {
                if (keyExchangeFactories == null) {
                    keyExchangeFactories = Arrays.asList(
                            new org.apache.sshd.client.kex.DHGEX256.Factory(),
                            new org.apache.sshd.client.kex.DHGEX.Factory(),
                            new org.apache.sshd.client.kex.ECDHP256.Factory(),
                            new org.apache.sshd.client.kex.ECDHP384.Factory(),
                            new org.apache.sshd.client.kex.ECDHP521.Factory(),
                            new org.apache.sshd.client.kex.DHG1.Factory());
                }
            } else {
                if (keyExchangeFactories == null) {
                    keyExchangeFactories = Arrays.asList(
                            new org.apache.sshd.client.kex.DHGEX256.Factory(),
                            new org.apache.sshd.client.kex.DHGEX.Factory(),
                            new org.apache.sshd.client.kex.DHG1.Factory());
                }
            }
            if (channelFactories == null) {
                channelFactories = Arrays.<NamedFactory<Channel>>asList(
                        new TcpipServerChannel.ForwardedTcpipFactory());
            }
            if (serverKeyVerifier == null) {
                serverKeyVerifier = AcceptAllServerKeyVerifier.INSTANCE;
            }
            if (factory == null) {
                factory = SshClient.DEFAULT_SSH_CLIENT_FACTORY;
            }
            return me();
        }

        @Override
        public SshClient build(boolean isFillWithDefaultValues) {
            SshClient client = super.build(isFillWithDefaultValues);
            client.setServerKeyVerifier(serverKeyVerifier);
            return client;
        }
    }

    /**
     * SshServer builder
     */
    public static class ServerBuilder extends BaseBuilder<SshServer, ServerBuilder> {

        @Override
        protected ServerBuilder fillWithDefaultValues() {
            super.fillWithDefaultValues();
            if (SecurityUtils.isBouncyCastleRegistered()) {
                if (keyExchangeFactories == null) {
                    keyExchangeFactories = Arrays.asList(
                            new org.apache.sshd.server.kex.DHGEX256.Factory(),
                            new org.apache.sshd.server.kex.DHGEX.Factory(),
                            new org.apache.sshd.server.kex.ECDHP256.Factory(),
                            new org.apache.sshd.server.kex.ECDHP384.Factory(),
                            new org.apache.sshd.server.kex.ECDHP521.Factory(),
                            new org.apache.sshd.server.kex.DHG14.Factory(),
                            new org.apache.sshd.server.kex.DHG1.Factory());
                }
            // EC keys are not supported until OpenJDK 7
            } else if (SecurityUtils.hasEcc()) {
                if (keyExchangeFactories == null) {
                    keyExchangeFactories = Arrays.asList(
                            new org.apache.sshd.server.kex.DHGEX256.Factory(),
                            new org.apache.sshd.server.kex.DHGEX.Factory(),
                            new org.apache.sshd.server.kex.ECDHP256.Factory(),
                            new org.apache.sshd.server.kex.ECDHP384.Factory(),
                            new org.apache.sshd.server.kex.ECDHP521.Factory(),
                            new org.apache.sshd.server.kex.DHG1.Factory());
                }
            } else {
                if (keyExchangeFactories == null) {
                    keyExchangeFactories = Arrays.asList(
                            new org.apache.sshd.server.kex.DHGEX256.Factory(),
                            new org.apache.sshd.server.kex.DHGEX.Factory(),
                            new org.apache.sshd.server.kex.DHG1.Factory());
                }
            }
            if (channelFactories == null) {
                channelFactories = Arrays.asList(
                        new ChannelSession.Factory(),
                        new TcpipServerChannel.DirectTcpipFactory());
            }
            if (globalRequestHandlers == null) {
                globalRequestHandlers = Arrays.asList(
                        new KeepAliveHandler(),
                        new NoMoreSessionsHandler(),
                        new TcpipForwardHandler(),
                        new CancelTcpipForwardHandler());
            }
            if (factory == null) {
                factory = SshServer.DEFAULT_SSH_SERVER_FACTORY;
            }
            return me();
        }
    }

}
