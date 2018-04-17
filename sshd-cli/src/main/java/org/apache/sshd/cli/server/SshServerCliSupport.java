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

import java.io.File;
import java.io.InputStream;
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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.cli.CliSupport;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.config.keys.BuiltinIdentities;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.keyprovider.MappedKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.ServerAuthenticationManager;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.config.SshServerConfigFileReader;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.subsystem.SubsystemFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SshServerCliSupport extends CliSupport {
    protected SshServerCliSupport() {
        super();
    }

    public static KeyPairProvider setupServerKeys(SshServer sshd, String hostKeyType, int hostKeySize, Collection<String> keyFiles) throws Exception {
        if (GenericUtils.isEmpty(keyFiles)) {
            AbstractGeneratorHostKeyProvider hostKeyProvider;
            Path hostKeyFile;
            if (SecurityUtils.isBouncyCastleRegistered()) {
                hostKeyFile = new File("key.pem").toPath();
                hostKeyProvider = SecurityUtils.createGeneratorHostKeyProvider(hostKeyFile);
            } else {
                hostKeyFile = new File("key.ser").toPath();
                hostKeyProvider = new SimpleGeneratorHostKeyProvider(hostKeyFile);
            }
            hostKeyProvider.setAlgorithm(hostKeyType);
            if (hostKeySize != 0) {
                hostKeyProvider.setKeySize(hostKeySize);
            }

            List<KeyPair> keys = ValidateUtils.checkNotNullAndNotEmpty(hostKeyProvider.loadKeys(),
                    "Failed to load keys from %s", hostKeyFile);
            KeyPair kp = keys.get(0);
            PublicKey pubKey = kp.getPublic();
            String keyAlgorithm = pubKey.getAlgorithm();
            if (BuiltinIdentities.Constants.ECDSA.equalsIgnoreCase(keyAlgorithm)) {
                keyAlgorithm = KeyUtils.EC_ALGORITHM;
            } else if (BuiltinIdentities.Constants.ED25519.equals(keyAlgorithm)) {
                keyAlgorithm = SecurityUtils.EDDSA;
                // TODO change the hostKeyProvider to one that supports read/write of EDDSA keys - see SSHD-703
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
                try (InputStream inputStream = Files.newInputStream(path)) {
                    KeyPair kp = SecurityUtils.loadKeyPairIdentity(keyFilePath, inputStream, null);
                    pairs.add(kp);
                } catch (Exception e) {
                    System.err.append("Failed (" + e.getClass().getSimpleName() + ")"
                                + " to load host key file=" + keyFilePath
                                + ": " + e.getMessage());
                    throw e;
                }
            }

            return new MappedKeyPairProvider(pairs);
        }
    }

    public static ForwardingFilter setupServerForwarding(SshServer server, PropertyResolver options) {
        ForwardingFilter forwardFilter = SshServerConfigFileReader.resolveServerForwarding(options);
        server.setForwardingFilter(forwardFilter);
        return forwardFilter;
    }

    public static Object setupServerBanner(ServerFactoryManager server, PropertyResolver options) {
        Object banner = SshServerConfigFileReader.resolveBanner(options);
        PropertyResolverUtils.updateProperty(server, ServerAuthenticationManager.WELCOME_BANNER, banner);
        return banner;
    }

    public static List<NamedFactory<Command>> setupServerSubsystems(SshServer server, PropertyResolver options) {
        ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(SubsystemFactory.class);
        String classList = System.getProperty(SubsystemFactory.class.getName());
        if (GenericUtils.isNotEmpty(classList)) {
            String[] classes = GenericUtils.split(classList, ',');
            List<NamedFactory<Command>> subsystems = new ArrayList<>(classes.length);
            for (String fqcn : classes) {
                try {
                    Class<?> clazz = cl.loadClass(fqcn);
                    SubsystemFactory factory = (SubsystemFactory) clazz.newInstance();
                    subsystems.add(factory);
                } catch (Throwable t) {
                    System.err.append("Failed (").append(t.getClass().getSimpleName()).append(')')
                        .append(" to instantiate subsystem=").append(fqcn)
                        .append(": ").println(t.getMessage());
                    System.err.flush();
                    throw GenericUtils.toRuntimeException(t, true);
                }
            }

            return subsystems;
        }

        String nameList = (options == null) ? null : options.getString(SshConfigFileReader.SUBSYSTEM_CONFIG_PROP);
        if ("none".equalsIgnoreCase(nameList)) {
            return Collections.emptyList();
        }

        boolean havePreferences = GenericUtils.isNotEmpty(nameList);
        Collection<String> preferredNames = (!havePreferences)
            ? Collections.emptySet()
            : Stream.of(GenericUtils.split(nameList, ','))
                .collect(Collectors.toCollection(() -> new TreeSet<>(String.CASE_INSENSITIVE_ORDER)));
        ServiceLoader<SubsystemFactory> loader = ServiceLoader.load(SubsystemFactory.class, cl);
        List<NamedFactory<Command>> subsystems = new ArrayList<>();
        for (SubsystemFactory factory : loader) {
            String name = factory.getName();
            if (havePreferences && (!preferredNames.contains(name))) {
                continue;
            }

            subsystems.add(factory);
        }

        return subsystems;
    }
}
