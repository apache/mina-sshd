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

package org.apache.sshd.server.auth;

import java.io.File;
import java.nio.file.Path;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.CoreSession;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.schema.SchemaPartition;
import org.apache.directory.server.core.schema.SchemaService;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.shared.ldap.entry.Entry;
import org.apache.directory.shared.ldap.entry.EntryAttribute;
import org.apache.directory.shared.ldap.ldif.ChangeType;
import org.apache.directory.shared.ldap.ldif.LdifEntry;
import org.apache.directory.shared.ldap.ldif.LdifReader;
import org.apache.directory.shared.ldap.message.AddRequestImpl;
import org.apache.directory.shared.ldap.message.internal.InternalAddRequest;
import org.apache.directory.shared.ldap.schema.SchemaManager;
import org.apache.directory.shared.ldap.schema.ldif.extractor.SchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.ldif.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.loader.ldif.LdifSchemaLoader;
import org.apache.directory.shared.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.shared.ldap.schema.registries.SchemaLoader;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Category({ NoIoTestCase.class })
public abstract class BaseAuthenticatorTest extends BaseTestSupport {
    public static final int PORT = Integer.parseInt(System.getProperty("org.apache.sshd.test.ldap.port", "11389"));
    public static final String BASE_DN_TEST = "ou=People,dc=sshd,dc=apache,dc=org";

    protected BaseAuthenticatorTest() {
        super();
    }

    public static String getHost(Map.Entry<LdapServer, DirectoryService> context) {
        return getHost((context == null) ? null : context.getKey());
    }

    public static String getHost(LdapServer ldapServer) {
        return getHost((ldapServer == null) ? null : ldapServer.getTransports());
    }

    public static String getHost(Transport... transports) {
        return GenericUtils.isEmpty(transports) ? null : transports[0].getAddress();
    }

    public static int getPort(Map.Entry<LdapServer, DirectoryService> context) {
        return getPort((context == null) ? null : context.getKey());
    }

    public static int getPort(LdapServer ldapServer) {
        return getPort((ldapServer == null) ? null : ldapServer.getTransports());
    }

    public static int getPort(Transport... transports) {
        return GenericUtils.isEmpty(transports) ? -1 : transports[0].getPort();
    }

    // see http://javlog.cacek.cz/2014/09/speed-up-apacheds-ldap-server.html
    // see https://cwiki.apache.org/confluence/display/DIRxSRVx11/4.1.+Embedding+ApacheDS+into+an+application
    // see http://stackoverflow.com/questions/1560230/running-apache-ds-embedded-in-my-application
    @SuppressWarnings("checkstyle:avoidnestedblocks")
    public static SimpleImmutableEntry<LdapServer, DirectoryService> startApacheDs(Class<?> anchor) throws Exception {
        Logger log = LoggerFactory.getLogger(anchor);
        Path targetFolder = Objects.requireNonNull(CommonTestSupportUtils.detectTargetFolder(anchor), "Failed to detect target folder");
        Path anchorFolder = CommonTestSupportUtils.resolve(targetFolder, anchor.getSimpleName(), "apacheds-work");
        Path workingDirectory = assertHierarchyTargetFolderExists(CommonTestSupportUtils.deleteRecursive(anchorFolder));

        DirectoryService directoryService = new DefaultDirectoryService();
        directoryService.setWorkingDirectory(workingDirectory.toFile());

        SchemaService schemaService = directoryService.getSchemaService();
        SchemaPartition schemaPartition = schemaService.getSchemaPartition();
        LdifPartition ldifPartition = new LdifPartition();
        // see DefaultSchemaLdifExtractor#SCHEMA...
        Path schemaRepository = assertHierarchyTargetFolderExists(workingDirectory.resolve("schema"));
        ldifPartition.setWorkingDirectory(Objects.toString(schemaRepository.toAbsolutePath(), null));

        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(workingDirectory.toFile());
        extractor.extractOrCopy(true);
        schemaPartition.setWrappedPartition(ldifPartition);

        SchemaLoader loader = new LdifSchemaLoader(schemaRepository.toFile());
        SchemaManager schemaManager = new DefaultSchemaManager(loader);
        directoryService.setSchemaManager(schemaManager);

        schemaManager.loadAllEnabled();

        schemaPartition.setSchemaManager(schemaManager);

        List<Throwable> errors = schemaManager.getErrors();
        if (GenericUtils.size(errors) > 0) {
            log.error("Schema management loading errors found");
            for (Throwable t : errors) {
                log.error(t.getClass().getSimpleName() + ": " + t.getMessage(), t);
            }
            throw new Exception("Schema load failed");
        }

        {
            JdbmPartition systemPartition = new JdbmPartition();
            systemPartition.setId("system");

            Path partitionFolder = CommonTestSupportUtils.deleteRecursive(workingDirectory.resolve(systemPartition.getId()));
            systemPartition.setPartitionDir(assertHierarchyTargetFolderExists(partitionFolder).toFile());
            systemPartition.setSuffix(ServerDNConstants.SYSTEM_DN);
            systemPartition.setSchemaManager(schemaManager);
            directoryService.setSystemPartition(systemPartition);
        }

        // Create a new partition for the users
        {
            JdbmPartition partition = new JdbmPartition();
            partition.setId("users");
            partition.setSuffix(BASE_DN_TEST);

            Path partitionFolder = CommonTestSupportUtils.deleteRecursive(workingDirectory.resolve(partition.getId()));
            partition.setPartitionDir(assertHierarchyTargetFolderExists(partitionFolder.toFile()));
            directoryService.addPartition(partition);
        }

        directoryService.setShutdownHookEnabled(true);
        directoryService.getChangeLog().setEnabled(false);

        LdapServer ldapServer = new LdapServer();
        ldapServer.setTransports(new TcpTransport(TEST_LOCALHOST, PORT));
        ldapServer.setDirectoryService(directoryService);

        log.info("Starting directory service ...");
        directoryService.startup();
        log.info("Directory service started");

        log.info("Starting LDAP server on port=" + getPort(ldapServer) + " ...");
        try {
            ldapServer.start();
            log.info("LDAP server started");
        } catch (Exception e) {
            log.error("Failed (" + e.getClass().getSimpleName() + ") to start LDAP server: " + e.getMessage(), e);
            stopApacheDs(directoryService);
            throw e;
        }

        return new SimpleImmutableEntry<>(ldapServer, directoryService);
    }

    // see http://users.directory.apache.narkive.com/GkyqAkot/how-to-import-ldif-file-programmatically
    public static NavigableMap<String, String> populateUsers(DirectoryService service, Class<?> anchor, String credentialName) throws Exception {
        Logger log = LoggerFactory.getLogger(anchor);
        CoreSession session = Objects.requireNonNull(service.getAdminSession(), "No core session");
        NavigableMap<String, String> usersMap = new TreeMap<>(Comparator.naturalOrder());
        try (LdifReader reader = new LdifReader(Objects.requireNonNull(anchor.getResourceAsStream("/auth-users.ldif"), "No users ldif"))) {
            int id = 1;
            for (LdifEntry entry : reader) {
                if (log.isDebugEnabled()) {
                    log.debug("Process LDIF entry={}", entry);
                }

                Entry data = entry.getEntry();
                EntryAttribute userAttr = data.get("uid");
                EntryAttribute passAttr = data.get(credentialName);
                if ((userAttr != null) && (passAttr != null)) {
                    String username = userAttr.getString();
                    ValidateUtils.checkTrue(usersMap.put(username, passAttr.getString()) == null, "Multiple entries for user=%s", username);
                }

                ChangeType changeType = entry.getChangeType();
                try {
                    switch (changeType) {
                        case Add: {
                            InternalAddRequest addRequest = new AddRequestImpl(id++);
                            addRequest.setEntry(data);
                            session.add(addRequest);
                            break;
                        }

                        default:
                            throw new UnsupportedOperationException("Unsupported change type (" + changeType + ") for entry=" + entry);
                    }
                } catch (Exception e) {
                    log.error("Failed (" + e.getClass().getSimpleName() + ") to add entry=" + entry + ": " + e.getMessage(), e);
                    throw e;
                }
            }
        }

        return usersMap;
    }

    public static void stopApacheDs(Map.Entry<LdapServer, DirectoryService> context) throws Exception {
        stopApacheDs((context == null) ? null : context.getKey());
        stopApacheDs((context == null) ? null : context.getValue());
    }

    public static void stopApacheDs(LdapServer ldapServer) throws Exception {
        if ((ldapServer == null) || (!ldapServer.isStarted())) {
            return;
        }

        Logger log = LoggerFactory.getLogger(BaseAuthenticatorTest.class);
        log.info("Stopping LDAP server...");
        ldapServer.stop();
        log.info("LDAP server stopped");
    }

    public static void stopApacheDs(DirectoryService directoryService) throws Exception {
        if ((directoryService == null) || (!directoryService.isStarted())) {
            return;
        }

        Logger log = LoggerFactory.getLogger(BaseAuthenticatorTest.class);
        File workDir = directoryService.getWorkingDirectory();

        log.info("Shutdown directory service ...");
        directoryService.shutdown();
        log.info("Directory service shut down");

        log.info("Deleting " + workDir.getAbsolutePath());
        CommonTestSupportUtils.deleteRecursive(workDir.toPath());
        log.info(workDir.getAbsolutePath() + " deleted");
    }
}
