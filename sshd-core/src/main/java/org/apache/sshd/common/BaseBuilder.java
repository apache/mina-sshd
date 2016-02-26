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

package org.apache.sshd.common;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.forward.DefaultTcpipForwarderFactory;
import org.apache.sshd.common.forward.TcpipForwarderFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.forward.RejectAllForwardingFilter;

/**
 * Base class for dedicated client/server instance builders
 *
 * @param <T> Type of {@link AbstractFactoryManager} being built
 * @param <S> Type of builder
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BaseBuilder<T extends AbstractFactoryManager, S extends BaseBuilder<T, S>> implements ObjectBuilder<T> {
    public static final FileSystemFactory DEFAULT_FILE_SYSTEM_FACTORY = NativeFileSystemFactory.INSTANCE;

    public static final ForwardingFilter DEFAULT_FORWARDING_FILTER = RejectAllForwardingFilter.INSTANCE;

    public static final TcpipForwarderFactory DEFAULT_FORWARDER_FACTORY = DefaultTcpipForwarderFactory.INSTANCE;

    /**
     * The default {@link BuiltinCiphers} setup in order of preference
     * as specified by <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">ssh_config(5)</A>
     */
    public static final List<BuiltinCiphers> DEFAULT_CIPHERS_PREFERENCE =
        Collections.unmodifiableList(Arrays.asList(
            BuiltinCiphers.aes128ctr,
            BuiltinCiphers.aes192ctr,
            BuiltinCiphers.aes256ctr,
            BuiltinCiphers.arcfour256,
            BuiltinCiphers.arcfour128,
            BuiltinCiphers.aes128cbc,
            BuiltinCiphers.tripledescbc,
            BuiltinCiphers.blowfishcbc,
            // TODO add support for cast128-cbc cipher
            BuiltinCiphers.aes192cbc,
            BuiltinCiphers.aes256cbc
            // TODO add support for arcfour cipher
        ));

    /**
     * The default {@link BuiltinDHFactories} setup in order of preference
     * as specified by <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">
     * ssh_config(5)</A>
     */
    public static final List<BuiltinDHFactories> DEFAULT_KEX_PREFERENCE =
        Collections.unmodifiableList(Arrays.asList(
            BuiltinDHFactories.ecdhp521,
            BuiltinDHFactories.ecdhp384,
            BuiltinDHFactories.ecdhp256,

            BuiltinDHFactories.dhgex256,
            BuiltinDHFactories.dhgex,

            BuiltinDHFactories.dhg14,
            BuiltinDHFactories.dhg1
        ));

    /**
     * The default {@link BuiltinMacs} setup in order of preference
     * as specified by <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">
     * ssh_config(5)</A>
     */
    public static final List<BuiltinMacs> DEFAULT_MAC_PREFERENCE =
        Collections.unmodifiableList(Arrays.asList(
            BuiltinMacs.hmacmd5,
            BuiltinMacs.hmacsha1,
            BuiltinMacs.hmacsha256,
            BuiltinMacs.hmacsha512,
            BuiltinMacs.hmacsha196,
            BuiltinMacs.hmacmd596
        ));

    /**
     * Preferred {@link BuiltinSignatures} according to
     * <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">sshd_config(5)</A>
     * {@code HostKeyAlgorithms} recommendation
     */
    public static final List<BuiltinSignatures> DEFAULT_SIGNATURE_PREFERENCE =
        Collections.unmodifiableList(Arrays.asList(
            BuiltinSignatures.nistp256,
            BuiltinSignatures.nistp384,
            BuiltinSignatures.nistp521,
            BuiltinSignatures.rsa,
            BuiltinSignatures.dsa
        ));

    protected Factory<T> factory;
    protected List<NamedFactory<KeyExchange>> keyExchangeFactories;
    protected List<NamedFactory<Cipher>> cipherFactories;
    protected List<NamedFactory<Compression>> compressionFactories;
    protected List<NamedFactory<Mac>> macFactories;
    protected List<NamedFactory<Signature>> signatureFactories;
    protected Factory<Random> randomFactory;
    protected List<NamedFactory<Channel>> channelFactories;
    protected FileSystemFactory fileSystemFactory;
    protected TcpipForwarderFactory tcpipForwarderFactory;
    protected List<RequestHandler<ConnectionService>> globalRequestHandlers;
    protected ForwardingFilter forwardingFilter;

    public BaseBuilder() {
        super();
    }

    protected S fillWithDefaultValues() {
        if (signatureFactories == null) {
            signatureFactories = setUpDefaultSignatures(false);
        }

        if (randomFactory == null) {
            randomFactory = new SingletonRandomFactory(SecurityUtils.getRandomFactory());
        }

        if (cipherFactories == null) {
            cipherFactories = setUpDefaultCiphers(false);
        }

        if (macFactories == null) {
            macFactories = setUpDefaultMacs(false);
        }

        if (fileSystemFactory == null) {
            fileSystemFactory = DEFAULT_FILE_SYSTEM_FACTORY;
        }

        if (forwardingFilter == null) {
            forwardingFilter = DEFAULT_FORWARDING_FILTER;
        }

        if (tcpipForwarderFactory == null) {
            tcpipForwarderFactory = DEFAULT_FORWARDER_FACTORY;
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

    public S forwardingFilter(final ForwardingFilter filter) {
        this.forwardingFilter = filter;
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
        ssh.setTcpipForwardingFilter(forwardingFilter);
        ssh.setTcpipForwarderFactory(tcpipForwarderFactory);
        ssh.setGlobalRequestHandlers(globalRequestHandlers);
        return ssh;
    }

    @Override
    public T build() {
        return build(true);
    }

    @SuppressWarnings("unchecked")
    protected S me() {
        return (S) this;
    }

    /**
     * @param ignoreUnsupported If {@code true} then all the default
     *                          ciphers are included, regardless of whether they are currently
     *                          supported by the JCE. Otherwise, only the supported ones out of the
     *                          list are included
     * @return A {@link List} of the default {@link NamedFactory}
     * instances of the {@link Cipher}s according to the preference
     * order defined by {@link #DEFAULT_CIPHERS_PREFERENCE}.
     * <B>Note:</B> the list may be filtered to exclude unsupported JCE
     * ciphers according to the <tt>ignoreUnsupported</tt> parameter
     * @see BuiltinCiphers#isSupported()
     */
    public static List<NamedFactory<Cipher>> setUpDefaultCiphers(boolean ignoreUnsupported) {
        return NamedFactory.Utils.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_CIPHERS_PREFERENCE);
    }

    /**
     * @param ignoreUnsupported If {@code true} all the available built-in
     *                          {@link Mac} factories are added, otherwise only those that are supported
     *                          by the current JDK setup
     * @return A {@link List} of the default {@link NamedFactory}
     * instances of the {@link Mac}s according to the preference
     * order defined by {@link #DEFAULT_MAC_PREFERENCE}.
     * <B>Note:</B> the list may be filtered to exclude unsupported JCE
     * MACs according to the <tt>ignoreUnsupported</tt> parameter
     * @see BuiltinMacs#isSupported()
     */
    public static List<NamedFactory<Mac>> setUpDefaultMacs(boolean ignoreUnsupported) {
        return NamedFactory.Utils.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_MAC_PREFERENCE);
    }

    /**
     * @param ignoreUnsupported If {@code true} all the available built-in
     *                          {@link Signature} factories are added, otherwise only those that are supported
     *                          by the current JDK setup
     * @return A {@link List} of the default {@link NamedFactory}
     * instances of the {@link Signature}s according to the preference
     * order defined by {@link #DEFAULT_SIGNATURE_PREFERENCE}.
     * <B>Note:</B> the list may be filtered to exclude unsupported JCE
     * signatures according to the <tt>ignoreUnsupported</tt> parameter
     * @see BuiltinSignatures#isSupported()
     */
    public static List<NamedFactory<Signature>> setUpDefaultSignatures(boolean ignoreUnsupported) {
        return NamedFactory.Utils.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_SIGNATURE_PREFERENCE);
    }
}