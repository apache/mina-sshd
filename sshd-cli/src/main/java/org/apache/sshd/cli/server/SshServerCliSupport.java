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

package org.apache.sshd.cli.server;

import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.cli.CliLogger;
import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.cli.server.helper.ScpCommandTransferEventListener;
import org.apache.sshd.cli.server.helper.ServerPortForwardingEventListener;
import org.apache.sshd.cli.server.helper.SftpServerSubSystemEventListener;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.ConfigFileReaderSupport;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.MappedKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.resource.PathResource;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.scp.server.ScpCommandFactory;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.config.SshServerConfigFileReader;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.InteractiveProcessShellFactory;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.server.SftpEventListener;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.slf4j.Logger;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SshServerCliSupport extends CliSupport {
    public static final String SHELL_FACTORY_OPTION = "ShellFactory";
    public static final ShellFactory DEFAULT_SHELL_FACTORY = InteractiveProcessShellFactory.INSTANCE;

    protected SshServerCliSupport() {
        super();
    }

    public static KeyPairProvider resolveServerKeys(
            PrintStream stderr, String hostKeyType, int hostKeySize, Collection<String> keyFiles)
            throws Exception {
        if (GenericUtils.isEmpty(keyFiles)) {
            AbstractGeneratorHostKeyProvider hostKeyProvider;
            Path hostKeyFile;
            if (SecurityUtils.isBouncyCastleRegistered()) {
                hostKeyFile = Paths.get("key.pem");
                hostKeyProvider = SecurityUtils.createGeneratorHostKeyProvider(hostKeyFile);
            } else {
                hostKeyFile = Paths.get("key.ser");
                hostKeyProvider = new SimpleGeneratorHostKeyProvider(hostKeyFile);
            }
            hostKeyProvider.setAlgorithm(hostKeyType);
            if (hostKeySize != 0) {
                hostKeyProvider.setKeySize(hostKeySize);
            }

            List<KeyPair> keys = ValidateUtils.checkNotNullAndNotEmpty(
                    hostKeyProvider.loadKeys(null), "Failed to load keys from %s", hostKeyFile);
            KeyPair kp = keys.get(0);
            PublicKey pubKey = kp.getPublic();
            String keyAlgorithm = pubKey.getAlgorithm();
            if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyAlgorithm)) {
                keyAlgorithm = KeyUtils.EC_ALGORITHM;
            } else if (BuiltinIdentities.Constants.ED25519.equals(keyAlgorithm)) {
                keyAlgorithm = SecurityUtils.EDDSA;
            }

            // force re-generation of host key if not same algorithm
            if (!Objects.equals(keyAlgorithm, hostKeyType)) {
                Files.deleteIfExists(hostKeyFile);
                hostKeyProvider.clearLoadedKeys();
            }

            return hostKeyProvider;
        } else {
            List<KeyPair> pairs = new ArrayList<>(keyFiles.size());
            for (String keyFilePath : keyFiles) {
                Path path = Paths.get(keyFilePath);
                PathResource location = new PathResource(path);
                Iterable<KeyPair> ids;
                try (InputStream inputStream = location.openInputStream()) {
                    ids = SecurityUtils.loadKeyPairIdentities(null, location, inputStream, null);
                } catch (Exception e) {
                    stderr.append("ERROR: Failed (").append(e.getClass().getSimpleName()).append(')')
                            .append(" to load host key file=").append(keyFilePath)
                            .append(": ").println(e.getMessage());
                    stderr.flush();
                    throw e;
                }

                if (ids == null) {
                    stderr.append("WARNING: No keys loaded from ").println(keyFilePath);
                    continue;
                }

                for (KeyPair kp : ids) {
                    if (kp == null) {
                        stderr.append("WARNING: empty key found in ").println(keyFilePath);
                        continue; // debug breakpoint
                    }
                    pairs.add(kp);
                }
            }

            return new MappedKeyPairProvider(
                    ValidateUtils.checkNotNullAndNotEmpty(pairs, "No key pairs loaded for provided key files"));
        }
    }

    public static ForwardingFilter setupServerForwarding(
            SshServer server, Level level, PrintStream stdout, PrintStream stderr, PropertyResolver options) {
        ForwardingFilter forwardFilter = SshServerConfigFileReader.resolveServerForwarding(options);
        server.setForwardingFilter(forwardFilter);
        if (CliLogger.isEnabledVerbosityLogging(level)) {
            Logger logger = CliLogger.resolveLogger(SshServerCliSupport.class, level, stdout, stderr);
            server.addPortForwardingEventListener(new ServerPortForwardingEventListener(logger));
        }
        return forwardFilter;
    }

    public static Object setupServerBanner(ServerFactoryManager server, PropertyResolver options) {
        Object banner = SshServerConfigFileReader.resolveBanner(options);
        CoreModuleProperties.WELCOME_BANNER.set(server, banner);
        return banner;
    }

    public static List<SubsystemFactory> resolveServerSubsystems(
            ServerFactoryManager server, Level level, PrintStream stdout, PrintStream stderr, PropertyResolver options)
            throws Exception {
        ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(SubsystemFactory.class);
        String classList = System.getProperty(SubsystemFactory.class.getName());
        if (GenericUtils.isNotEmpty(classList)) {
            String[] classes = GenericUtils.split(classList, ',');
            List<SubsystemFactory> subsystems = new ArrayList<>(classes.length);
            for (String fqcn : classes) {
                try {
                    Class<?> clazz = cl.loadClass(fqcn);
                    SubsystemFactory factory = ReflectionUtils.newInstance(clazz, SubsystemFactory.class);
                    factory = registerSubsystemFactoryListeners(
                            server, level, stdout, stderr, options, factory);
                    subsystems.add(factory);
                } catch (Exception e) {
                    stderr.append("ERROR: Failed (").append(e.getClass().getSimpleName()).append(')')
                            .append(" to instantiate subsystem=").append(fqcn)
                            .append(": ").println(e.getMessage());
                    stderr.flush();
                    throw e;
                }
            }

            return subsystems;
        }

        String nameList = (options == null) ? null : options.getString(ConfigFileReaderSupport.SUBSYSTEM_CONFIG_PROP);
        if (PropertyResolverUtils.isNoneValue(nameList)) {
            return Collections.emptyList();
        }

        if (SftpConstants.SFTP_SUBSYSTEM_NAME.equalsIgnoreCase(nameList)) {
            SubsystemFactory factory = registerSubsystemFactoryListeners(
                    server, level, stdout, stderr, options, new SftpSubsystemFactory());
            PrintStream logStream = CliLogger.resolvePrintStream(level, stdout, stderr);
            CliLogger.log(logStream, level, "Using built-in SFTP subsystem");
            return Collections.singletonList(factory);
        }

        boolean havePreferences = GenericUtils.isNotEmpty(nameList);
        Collection<String> preferredNames = (!havePreferences)
                ? Collections.emptySet()
                : Stream.of(GenericUtils.split(nameList, ','))
                        .collect(Collectors.toCollection(() -> new TreeSet<>(String.CASE_INSENSITIVE_ORDER)));
        ServiceLoader<SubsystemFactory> loader = ServiceLoader.load(SubsystemFactory.class, cl);
        List<SubsystemFactory> subsystems = new ArrayList<>();
        for (SubsystemFactory factory : loader) {
            String name = factory.getName();
            if (havePreferences && (!preferredNames.contains(name))) {
                continue;
            }

            factory = registerSubsystemFactoryListeners(
                    server, level, stdout, stderr, options, factory);
            subsystems.add(factory);
        }

        return subsystems;
    }

    public static <F extends SubsystemFactory> F registerSubsystemFactoryListeners(
            ServerFactoryManager server, Level level, PrintStream stdout, PrintStream stderr, PropertyResolver options,
            F factory)
            throws Exception {
        if (factory instanceof SftpSubsystemFactory) {
            if (CliLogger.isEnabledVerbosityLogging(level)) {
                Logger logger = CliLogger.resolveLogger(SftpEventListener.class, level, stdout, stderr);
                SftpEventListener listener = new SftpServerSubSystemEventListener(logger);
                ((SftpSubsystemFactory) factory).addSftpEventListener(listener);
            }

            SshServerConfigFileReader.setupSftpSubsystem(server, options);
        }

        return factory;
    }

    /**
     * Attempts to examine the {@link #SHELL_FACTORY_OPTION} configuration.
     * <UL>
     * <LI>If missing/empty then returns the {@link #DEFAULT_SHELL_FACTORY}.</LI>
     *
     * <LI>If {@link PropertyResolverUtils#isNoneValue(String) NONE} then returns {@code null}</LI>
     *
     * <LI>If {@link ScpCommandFactory#SCP_FACTORY_NAME SCP} then returns a {@link ScpCommandFactory}</LI>
     *
     * <LI>Otherwise, assumes this is a fully qualified class path of a {@link ShellFactory} implementation and attempts
     * to load and instantiate it using a public no-args constructor</LI>
     * </UL>
     *
     * @param  level     The verbosity {@link Level}
     * @param  stdout    The STDOUT stream for logging
     * @param  stderr    The STDERR stream for errors
     * @param  options   The available options - assuming defaults if {@code null}
     * @return           The resolved {@link ShellFactory}
     * @throws Exception If failed to resolve
     */
    public static ShellFactory resolveShellFactory(
            Level level, PrintStream stdout, PrintStream stderr, PropertyResolver options)
            throws Exception {
        String factory = (options == null) ? null : options.getString(SHELL_FACTORY_OPTION);
        if (GenericUtils.isEmpty(factory)) {
            return DEFAULT_SHELL_FACTORY;
        }

        if (PropertyResolverUtils.isNoneValue(factory)) {
            return null;
        }

        // Only SCP
        if (ScpCommandFactory.SCP_FACTORY_NAME.equalsIgnoreCase(factory)) {
            return createScpCommandFactory(level, stdout, stderr, null);
        }

        // SCP + DEFAULT SHELL
        if (("+" + ScpCommandFactory.SCP_FACTORY_NAME).equalsIgnoreCase(factory)) {
            return createScpCommandFactory(level, stdout, stderr, DEFAULT_SHELL_FACTORY);
        }

        boolean useScp = false;
        // SCP + CUSTOM SHELL
        if (factory.startsWith(ScpCommandFactory.SCP_FACTORY_NAME + "+")) {
            factory = factory.substring(ScpCommandFactory.SCP_FACTORY_NAME.length() + 1);
            ValidateUtils.checkNotNullAndNotEmpty(factory, "No extra custom shell factory class specified");
            useScp = true;
        }

        ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(ShellFactory.class);
        try {
            Class<?> clazz = cl.loadClass(factory);
            ShellFactory shellFactory = ReflectionUtils.newInstance(clazz, ShellFactory.class);
            return useScp ? createScpCommandFactory(level, stdout, stderr, shellFactory) : shellFactory;
        } catch (Exception e) {
            stderr.append("ERROR: Failed (").append(e.getClass().getSimpleName()).append(')')
                    .append(" to instantiate shell factory=").append(factory)
                    .append(": ").println(e.getMessage());
            stderr.flush();
            throw e;
        }
    }

    public static ScpCommandFactory createScpCommandFactory(
            Level level, PrintStream stdout, PrintStream stderr, ShellFactory delegateShellFactory) {
        ScpCommandFactory.Builder scp = new ScpCommandFactory.Builder()
                .withDelegate(ProcessShellCommandFactory.INSTANCE)
                .withDelegateShellFactory(delegateShellFactory);
        if (CliLogger.isEnabledVerbosityLogging(level)) {
            Logger logger = CliLogger.resolveLogger(ScpTransferEventListener.class, level, stdout, stderr);
            scp.addEventListener(new ScpCommandTransferEventListener(logger));
        }

        return scp.build();
    }
}
