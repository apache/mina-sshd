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

package org.apache.sshd.sftp.server;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Supplier;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ManagedExecutorServiceSupplier;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.apache.sshd.sftp.common.SftpConstants;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystemFactory
        extends AbstractSftpEventListenerManager
        implements ManagedExecutorServiceSupplier, SubsystemFactory,
        SftpEventListenerManager, SftpFileSystemAccessorManager {

    public static final String NAME = SftpConstants.SFTP_SUBSYSTEM_NAME;
    public static final UnsupportedAttributePolicy DEFAULT_POLICY = UnsupportedAttributePolicy.Warn;

    public static class Builder extends AbstractSftpEventListenerManager implements ObjectBuilder<SftpSubsystemFactory> {
        private Supplier<? extends CloseableExecutorService> executorsProvider;
        private UnsupportedAttributePolicy policy = DEFAULT_POLICY;
        private SftpFileSystemAccessor fileSystemAccessor = SftpFileSystemAccessor.DEFAULT;
        private SftpErrorStatusDataHandler errorStatusDataHandler = SftpErrorStatusDataHandler.DEFAULT;

        public Builder() {
            super();
        }

        public Builder withExecutorServiceProvider(Supplier<? extends CloseableExecutorService> provider) {
            executorsProvider = provider;
            return this;
        }

        public Builder withUnsupportedAttributePolicy(UnsupportedAttributePolicy p) {
            policy = Objects.requireNonNull(p, "No policy");
            return this;
        }

        public Builder withFileSystemAccessor(SftpFileSystemAccessor accessor) {
            fileSystemAccessor = Objects.requireNonNull(accessor, "No accessor");
            return this;
        }

        public Builder withSftpErrorStatusDataHandler(SftpErrorStatusDataHandler handler) {
            errorStatusDataHandler = Objects.requireNonNull(handler, "No error status handler");
            return this;
        }

        @Override
        public SftpSubsystemFactory build() {
            SftpSubsystemFactory factory = new SftpSubsystemFactory();
            factory.setExecutorServiceProvider(executorsProvider);
            factory.setUnsupportedAttributePolicy(policy);
            factory.setFileSystemAccessor(fileSystemAccessor);
            factory.setErrorStatusDataHandler(errorStatusDataHandler);
            GenericUtils.forEach(getRegisteredListeners(), factory::addSftpEventListener);
            return factory;
        }
    }

    private Supplier<? extends CloseableExecutorService> executorsProvider;
    private UnsupportedAttributePolicy policy = DEFAULT_POLICY;
    private SftpFileSystemAccessor fileSystemAccessor = SftpFileSystemAccessor.DEFAULT;
    private SftpErrorStatusDataHandler errorStatusDataHandler = SftpErrorStatusDataHandler.DEFAULT;

    public SftpSubsystemFactory() {
        super();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Supplier<? extends CloseableExecutorService> getExecutorServiceProvider() {
        return executorsProvider;
    }

    @Override
    public void setExecutorServiceProvider(
            Supplier<? extends CloseableExecutorService> provider) {
        executorsProvider = provider;
    }

    public UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return policy;
    }

    /**
     * @param p The {@link UnsupportedAttributePolicy} to use if failed to access some local file attributes - never
     *          {@code null}
     */
    public void setUnsupportedAttributePolicy(UnsupportedAttributePolicy p) {
        policy = Objects.requireNonNull(p, "No policy");
    }

    @Override
    public SftpFileSystemAccessor getFileSystemAccessor() {
        return fileSystemAccessor;
    }

    @Override
    public void setFileSystemAccessor(SftpFileSystemAccessor accessor) {
        fileSystemAccessor = Objects.requireNonNull(accessor, "No accessor");
    }

    public SftpErrorStatusDataHandler getErrorStatusDataHandler() {
        return errorStatusDataHandler;
    }

    public void setErrorStatusDataHandler(SftpErrorStatusDataHandler handler) {
        errorStatusDataHandler = Objects.requireNonNull(handler, "No error status data handler provided");
    }

    @Override
    public Command createSubsystem(ChannelSession channel) throws IOException {
        SftpSubsystem subsystem = new SftpSubsystem(
                resolveExecutorService(),
                getUnsupportedAttributePolicy(), getFileSystemAccessor(),
                getErrorStatusDataHandler());
        GenericUtils.forEach(getRegisteredListeners(), subsystem::addSftpEventListener);
        return subsystem;
    }
}
