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
package org.apache.sshd.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.auth.UserAuthFactoriesManager;
import org.apache.sshd.common.auth.UserAuthInstance;
import org.apache.sshd.common.auth.UserAuthMethodFactory;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.config.CompressionConfigValue;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.io.BuiltinIoServiceFactoryFactories;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.GenericUtils;
import org.slf4j.Logger;

/**
 * Provides common utilities for SSH client/server execution from the CLI
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class CliSupport {
    public static final BuiltinIoServiceFactoryFactories DEFAULT_IO_SERVICE_FACTORY = BuiltinIoServiceFactoryFactories.NIO2;

    protected CliSupport() {
        super();
    }

    public static <
            S extends SessionContext,
            M extends UserAuthInstance<S>, F extends UserAuthMethodFactory<S, M>,
            I extends UserAuthFactoriesManager<S, M, F>> void setupUserAuthFactories(
                    I manager, PropertyResolver options) {
        String methods = options.getString(ConfigFileReaderSupport.PREFERRED_AUTHS_CONFIG_PROP);
        if (GenericUtils.isNotEmpty(methods)) {
            manager.setUserAuthFactoriesNameList(methods);
            return;
        }
    }

    /**
     * Scans the arguments for the &quot;-io&quot; command line option and sets the I/O service accordingly. If no
     * specific option specified then {@link #DEFAULT_IO_SERVICE_FACTORY} is used.
     *
     * @param  stderr Error stream for output of error messages
     * @param  args   The arguments to scan
     * @return        The resolved I/O service factory - {@code null} if errors encountered
     */
    public static BuiltinIoServiceFactoryFactories resolveIoServiceFactory(PrintStream stderr, String... args) {
        int numArgs = GenericUtils.length(args);
        BuiltinIoServiceFactoryFactories factory = null;
        for (int index = 0; index < numArgs; index++) {
            String argName = args[index];
            if (!"-io".equals(argName)) {
                continue;
            }

            if (factory != null) {
                stderr.println("I/O factory re-specified - already set as " + factory);
                return null;
            }

            index++;
            if (index >= numArgs) {
                stderr.println("option requires an argument: " + argName);
                return null;
            }

            String provider = args[index];
            factory = resolveBuiltinIoServiceFactory(stderr, argName, provider);
            if (factory == null) {
                return null;
            }
        }

        if (factory == null) {
            factory = DEFAULT_IO_SERVICE_FACTORY;
        }

        System.setProperty(IoServiceFactoryFactory.class.getName(), factory.getFactoryClassName());
        return factory;
    }

    public static BuiltinIoServiceFactoryFactories resolveBuiltinIoServiceFactory(
            PrintStream stderr, String argName, String provider) {
        BuiltinIoServiceFactoryFactories factory = BuiltinIoServiceFactoryFactories.fromFactoryName(provider);
        if (factory == null) {
            System.err.println(argName + " - unknown provider (" + provider + ")"
                               + " should be one of " + BuiltinIoServiceFactoryFactories.VALUES);
        }
        return factory;
    }

    public static <M extends AbstractFactoryManager> M setupIoServiceFactory(
            M manager, PropertyResolver resolver, Level level,
            PrintStream stdout, PrintStream stderr, String... args) {
        BuiltinIoServiceFactoryFactories factory = resolveIoServiceFactory(stderr, args);
        if (factory == null) {
            return null;
        }

        manager.setIoServiceFactoryFactory(factory.create());

        Logger logger = CliLogger.resolveLogger(CliSupport.class, level, stdout, stderr);
        if (logger.isInfoEnabled()) {
            manager.setIoServiceEventListener(createLoggingIoServiceEventListener(logger));
            manager.addSessionListener(createLoggingSessionListener(logger));
        }
        return manager;
    }

    @SuppressWarnings("checkstyle:anoninnerlength")
    public static IoServiceEventListener createLoggingIoServiceEventListener(Logger logger) {
        return new IoServiceEventListener() {
            @Override
            public void connectionEstablished(
                    IoConnector connector, SocketAddress local, AttributeRepository context, SocketAddress remote)
                    throws IOException {
                logger.info("Connection established via {} - local={}, remote={}", connector, local, remote);
            }

            @Override
            public void abortEstablishedConnection(
                    IoConnector connector, SocketAddress local, AttributeRepository context,
                    SocketAddress remote, Throwable reason)
                    throws IOException {
                logger.info("Abort established connection {}  - local={}, remote={}", connector, local, remote);
                if (reason != null) {
                    logger.warn("     {}: {}", reason.getClass().getSimpleName(), reason.getMessage());
                    logger.error(reason.getClass().getSimpleName(), reason);
                }
            }

            @Override
            public void connectionAccepted(
                    IoAcceptor acceptor, SocketAddress local,
                    SocketAddress remote, SocketAddress service)
                    throws IOException {
                logger.info("Connection accepted via {} - local={}, remote={}, service={}", acceptor, local, remote, service);
            }

            @Override
            public void abortAcceptedConnection(
                    IoAcceptor acceptor, SocketAddress local, SocketAddress remote,
                    SocketAddress service, Throwable reason)
                    throws IOException {
                logger.info("Abort accepted connection {} - local={}, remote={}, service={}", acceptor, local, remote, service);
                if (reason != null) {
                    logger.warn("     {}: {}", reason.getClass().getSimpleName(), reason.getMessage());
                    logger.error(reason.getClass().getSimpleName(), reason);
                }
            }
        };
    }

    @SuppressWarnings("checkstyle:anoninnerlength")
    public static SessionListener createLoggingSessionListener(Logger logger) {
        return new SessionListener() {
            @Override
            public void sessionPeerIdentificationReceived(
                    Session session, String version, List<String> extraLines) {
                logger.info("{} peer identification={}", session, version);
                if (GenericUtils.isNotEmpty(extraLines)) {
                    for (String l : extraLines) {
                        logger.info("    => {}", l);
                    }
                }
            }

            @Override
            public void sessionNegotiationEnd(
                    Session session,
                    Map<KexProposalOption, String> clientProposal,
                    Map<KexProposalOption, String> serverProposal,
                    Map<KexProposalOption, String> negotiatedOptions,
                    Throwable reason) {
                if (reason != null) {
                    return;
                }

                logger.info("{} KEX negotiation results:", session);
                for (KexProposalOption opt : KexProposalOption.VALUES) {
                    logger.info("    {}: {}", opt.getDescription(), negotiatedOptions.get(opt));
                }
            }

            @Override
            public void sessionException(Session session, Throwable t) {
                logger.error("{} {}: {}", session, t.getClass().getSimpleName(), t.getMessage());
                logger.error(t.getClass().getSimpleName(), t);
            }

            @Override
            public void sessionClosed(Session session) {
                logger.info("{} closed", session);
            }
        };
    }

    public static List<NamedFactory<Compression>> setupCompressions(PropertyResolver options, PrintStream stderr) {
        String argVal = PropertyResolverUtils.getString(
                options, ConfigFileReaderSupport.COMPRESSION_PROP);
        if (GenericUtils.isEmpty(argVal)) {
            return Collections.emptyList();
        }

        NamedFactory<Compression> value = CompressionConfigValue.fromName(argVal);
        if (value == null) {
            CliLogger.showError(stderr, "Unknown compression configuration value: " + argVal);
            return null;
        }

        return Collections.singletonList(value);
    }

    public static List<NamedFactory<Compression>> setupCompressions(
            String argName, String argVal, List<NamedFactory<Compression>> current, PrintStream stderr) {
        if (GenericUtils.size(current) > 0) {
            CliLogger.showError(stderr, argName + " option value re-specified: " + NamedResource.getNames(current));
            return null;
        }

        BuiltinCompressions.ParseResult result = BuiltinCompressions.parseCompressionsList(argVal);
        Collection<? extends NamedFactory<Compression>> available = result.getParsedFactories();
        if (GenericUtils.isEmpty(available)) {
            CliLogger.showError(stderr, "No known compressions in " + argVal);
            return null;
        }

        Collection<String> unsupported = result.getUnsupportedFactories();
        if (GenericUtils.size(unsupported) > 0) {
            stderr.append("WARNING: Ignored unsupported compressions: ")
                    .println(GenericUtils.join(unsupported, ','));
        }

        return new ArrayList<>(available);
    }

    public static List<NamedFactory<Mac>> setupMacs(PropertyResolver options, PrintStream stderr) {
        String argVal = PropertyResolverUtils.getString(
                options, ConfigFileReaderSupport.MACS_CONFIG_PROP);
        return GenericUtils.isEmpty(argVal)
                ? Collections.emptyList()
                : CliSupport.setupMacs(ConfigFileReaderSupport.MACS_CONFIG_PROP, argVal, null, stderr);
    }

    public static List<NamedFactory<Mac>> setupMacs(
            String argName, String argVal, List<NamedFactory<Mac>> current, PrintStream stderr) {
        if (GenericUtils.size(current) > 0) {
            CliLogger.showError(stderr, argName + " option value re-specified: " + NamedResource.getNames(current));
            return null;
        }

        BuiltinMacs.ParseResult result = BuiltinMacs.parseMacsList(argVal);
        Collection<? extends NamedFactory<Mac>> available = result.getParsedFactories();
        if (GenericUtils.isEmpty(available)) {
            CliLogger.showError(stderr, "No known MACs in " + argVal);
            return null;
        }

        Collection<String> unsupported = result.getUnsupportedFactories();
        if (GenericUtils.size(unsupported) > 0) {
            stderr.append("WARNING: Ignored unsupported MACs: ")
                    .println(GenericUtils.join(unsupported, ','));
        }

        return new ArrayList<>(available);
    }

    public static List<NamedFactory<Cipher>> setupCiphers(PropertyResolver options, PrintStream stderr) {
        String argVal = PropertyResolverUtils.getString(
                options, ConfigFileReaderSupport.CIPHERS_CONFIG_PROP);
        return GenericUtils.isEmpty(argVal)
                ? Collections.emptyList()
                : CliSupport.setupCiphers(ConfigFileReaderSupport.CIPHERS_CONFIG_PROP, argVal, null, stderr);
    }

    // returns null - e.g., re-specified or no supported cipher found
    public static List<NamedFactory<Cipher>> setupCiphers(
            String argName, String argVal, List<NamedFactory<Cipher>> current, PrintStream stderr) {
        if (GenericUtils.size(current) > 0) {
            CliLogger.showError(stderr, argName + " option value re-specified: " + NamedResource.getNames(current));
            return null;
        }

        BuiltinCiphers.ParseResult result = BuiltinCiphers.parseCiphersList(argVal);
        Collection<? extends NamedFactory<Cipher>> available = result.getParsedFactories();
        if (GenericUtils.isEmpty(available)) {
            CliLogger.showError(stderr, "WARNING: No known ciphers in " + argVal);
            return null;
        }

        Collection<String> unsupported = result.getUnsupportedFactories();
        if (GenericUtils.size(unsupported) > 0) {
            stderr.append("WARNING: Ignored unsupported ciphers: ")
                    .println(GenericUtils.join(unsupported, ','));
        }

        return new ArrayList<>(available);
    }
}
