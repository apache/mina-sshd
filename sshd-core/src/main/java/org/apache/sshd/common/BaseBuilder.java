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

import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolver;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.forward.DefaultForwarderFactory;
import org.apache.sshd.common.forward.ForwarderFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.random.SingletonRandomFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.UnknownChannelReferenceHandler;
import org.apache.sshd.common.session.helpers.DefaultUnknownChannelReferenceHandler;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.forward.RejectAllForwardingFilter;

/**
 * Base class for dedicated client/server instance builders
 *
 * @param  <T> Type of {@link AbstractFactoryManager} being built
 * @param  <S> Type of builder
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BaseBuilder<T extends AbstractFactoryManager, S extends BaseBuilder<T, S>> implements ObjectBuilder<T> {
    public static final FileSystemFactory DEFAULT_FILE_SYSTEM_FACTORY = NativeFileSystemFactory.INSTANCE;

    public static final ForwardingFilter DEFAULT_FORWARDING_FILTER = RejectAllForwardingFilter.INSTANCE;

    public static final ForwarderFactory DEFAULT_FORWARDER_FACTORY = DefaultForwarderFactory.INSTANCE;

    /**
     * The default {@link BuiltinCiphers} setup in order of preference as specified by
     * <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5">ssh_config(5)</A>
     */
    public static final List<BuiltinCiphers> DEFAULT_CIPHERS_PREFERENCE = Collections.unmodifiableList(
            Arrays.asList(
                    BuiltinCiphers.aes128ctr,
                    BuiltinCiphers.aes192ctr,
                    BuiltinCiphers.aes256ctr,
                    BuiltinCiphers.aes128gcm,
                    BuiltinCiphers.aes256gcm,
                    BuiltinCiphers.aes128cbc,
                    BuiltinCiphers.aes192cbc,
                    BuiltinCiphers.aes256cbc));

    /**
     * The default {@link BuiltinDHFactories} setup in order of preference as specified by
     * <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5"> ssh_config(5)</A>
     */
    public static final List<BuiltinDHFactories> DEFAULT_KEX_PREFERENCE = Collections.unmodifiableList(
            Arrays.asList(
                    BuiltinDHFactories.ecdhp521,
                    BuiltinDHFactories.ecdhp384,
                    BuiltinDHFactories.ecdhp256,

                    BuiltinDHFactories.dhgex256,

                    BuiltinDHFactories.dhg18_512,
                    BuiltinDHFactories.dhg17_512,
                    BuiltinDHFactories.dhg16_512,
                    BuiltinDHFactories.dhg15_512,
                    BuiltinDHFactories.dhg14_256));

    /**
     * The default {@link BuiltinMacs} setup in order of preference as specified by
     * <A HREF="https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5"> ssh_config(5)</A>
     */
    public static final List<BuiltinMacs> DEFAULT_MAC_PREFERENCE = Collections.unmodifiableList(
            Arrays.asList(
                    BuiltinMacs.hmacsha256etm,
                    BuiltinMacs.hmacsha512etm,
                    BuiltinMacs.hmacsha1etm,
                    BuiltinMacs.hmacsha256,
                    BuiltinMacs.hmacsha512,
                    BuiltinMacs.hmacsha1));

    /**
     * Preferred {@link BuiltinSignatures} according to
     * <A HREF="http://man7.org/linux/man-pages/man5/sshd_config.5.html">sshd_config(5) - HostKeyAlgorithms</A>
     * {@code HostKeyAlgorithms} recommendation
     */
    public static final List<BuiltinSignatures> DEFAULT_SIGNATURE_PREFERENCE = Collections.unmodifiableList(
            Arrays.asList(
                    BuiltinSignatures.nistp256_cert,
                    BuiltinSignatures.nistp384_cert,
                    BuiltinSignatures.nistp521_cert,
                    BuiltinSignatures.ed25519_cert,
                    BuiltinSignatures.rsaSHA512_cert,
                    BuiltinSignatures.rsaSHA256_cert,
                    BuiltinSignatures.nistp256,
                    BuiltinSignatures.nistp384,
                    BuiltinSignatures.nistp521,
                    BuiltinSignatures.ed25519,
                    BuiltinSignatures.sk_ecdsa_sha2_nistp256,
                    BuiltinSignatures.sk_ssh_ed25519,
                    BuiltinSignatures.rsaSHA512,
                    BuiltinSignatures.rsaSHA256,
                    BuiltinSignatures.rsa));

    public static final UnknownChannelReferenceHandler DEFAULT_UNKNOWN_CHANNEL_REFERENCE_HANDLER
            = DefaultUnknownChannelReferenceHandler.INSTANCE;

    protected Factory<T> factory;
    protected List<KeyExchangeFactory> keyExchangeFactories;
    protected List<NamedFactory<Cipher>> cipherFactories;
    protected List<NamedFactory<Compression>> compressionFactories;
    protected List<NamedFactory<Mac>> macFactories;
    protected List<NamedFactory<Signature>> signatureFactories;
    protected Factory<Random> randomFactory;
    protected List<ChannelFactory> channelFactories;
    protected FileSystemFactory fileSystemFactory;
    protected ForwarderFactory forwarderFactory;
    protected List<RequestHandler<ConnectionService>> globalRequestHandlers;
    protected ForwardingFilter forwardingFilter;
    protected ChannelStreamWriterResolver channelStreamPacketWriterResolver;
    protected UnknownChannelReferenceHandler unknownChannelReferenceHandler;

    public BaseBuilder() {
        super();
    }

    protected S fillWithDefaultValues() {
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

        if (forwarderFactory == null) {
            forwarderFactory = DEFAULT_FORWARDER_FACTORY;
        }

        if (unknownChannelReferenceHandler == null) {
            unknownChannelReferenceHandler = DEFAULT_UNKNOWN_CHANNEL_REFERENCE_HANDLER;
        }

        return me();
    }

    public S keyExchangeFactories(List<KeyExchangeFactory> keyExchangeFactories) {
        this.keyExchangeFactories = keyExchangeFactories;
        return me();
    }

    public S signatureFactories(List<NamedFactory<Signature>> signatureFactories) {
        this.signatureFactories = signatureFactories;
        return me();
    }

    public S randomFactory(Factory<Random> randomFactory) {
        this.randomFactory = randomFactory;
        return me();
    }

    public S cipherFactories(List<NamedFactory<Cipher>> cipherFactories) {
        this.cipherFactories = cipherFactories;
        return me();
    }

    public S compressionFactories(List<NamedFactory<Compression>> compressionFactories) {
        this.compressionFactories = compressionFactories;
        return me();
    }

    public S macFactories(List<NamedFactory<Mac>> macFactories) {
        this.macFactories = macFactories;
        return me();
    }

    public S channelFactories(List<ChannelFactory> channelFactories) {
        this.channelFactories = channelFactories;
        return me();
    }

    public S fileSystemFactory(FileSystemFactory fileSystemFactory) {
        this.fileSystemFactory = fileSystemFactory;
        return me();
    }

    public S forwardingFilter(ForwardingFilter filter) {
        this.forwardingFilter = filter;
        return me();
    }

    public S forwarderFactory(ForwarderFactory forwarderFactory) {
        this.forwarderFactory = forwarderFactory;
        return me();
    }

    public S globalRequestHandlers(List<RequestHandler<ConnectionService>> globalRequestHandlers) {
        this.globalRequestHandlers = globalRequestHandlers;
        return me();
    }

    public S factory(Factory<T> factory) {
        this.factory = factory;
        return me();
    }

    public S channelStreamPacketWriterResolver(ChannelStreamWriterResolver resolver) {
        channelStreamPacketWriterResolver = resolver;
        return me();
    }

    public S unknownChannelReferenceHandler(UnknownChannelReferenceHandler handler) {
        unknownChannelReferenceHandler = handler;
        return me();
    }

    public T build(boolean isFillWithDefaultValues) {
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
        ssh.setForwardingFilter(forwardingFilter);
        ssh.setForwarderFactory(forwarderFactory);
        ssh.setGlobalRequestHandlers(globalRequestHandlers);
        ssh.setChannelStreamWriterResolver(channelStreamPacketWriterResolver);
        ssh.setUnknownChannelReferenceHandler(unknownChannelReferenceHandler);
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
     * @param  ignoreUnsupported If {@code true} then all the default ciphers are included, regardless of whether they
     *                           are currently supported by the JCE. Otherwise, only the supported ones out of the list
     *                           are included
     * @return                   A {@link List} of the default {@link NamedFactory} instances of the {@link Cipher}s
     *                           according to the preference order defined by {@link #DEFAULT_CIPHERS_PREFERENCE}.
     *                           <B>Note:</B> the list may be filtered to exclude unsupported JCE ciphers according to
     *                           the <tt>ignoreUnsupported</tt> parameter
     * @see                      BuiltinCiphers#isSupported()
     */
    @SuppressWarnings({ "unchecked", "rawtypes" }) // safe due to the hierarchy
    public static List<NamedFactory<Cipher>> setUpDefaultCiphers(boolean ignoreUnsupported) {
        return (List) NamedFactory.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_CIPHERS_PREFERENCE);
    }

    /**
     * @param  ignoreUnsupported If {@code true} all the available built-in {@link Mac} factories are added, otherwise
     *                           only those that are supported by the current JDK setup
     * @return                   A {@link List} of the default {@link NamedFactory} instances of the {@link Mac}s
     *                           according to the preference order defined by {@link #DEFAULT_MAC_PREFERENCE}.
     *                           <B>Note:</B> the list may be filtered to exclude unsupported JCE MACs according to the
     *                           <tt>ignoreUnsupported</tt> parameter
     * @see                      BuiltinMacs#isSupported()
     */
    @SuppressWarnings({ "unchecked", "rawtypes" }) // safe due to the hierarchy
    public static List<NamedFactory<Mac>> setUpDefaultMacs(boolean ignoreUnsupported) {
        return (List) NamedFactory.setUpBuiltinFactories(ignoreUnsupported, DEFAULT_MAC_PREFERENCE);
    }
}
