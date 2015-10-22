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

package org.apache.sshd.server.subsystem.sftp;

import java.util.Collection;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.subsystem.sftp.SftpConstants;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.subsystem.SubsystemFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpSubsystemFactory extends AbstractSftpEventListenerManager implements SubsystemFactory, ExecutorServiceConfigurer, SftpEventListenerManager {
    public static final String NAME = SftpConstants.SFTP_SUBSYSTEM_NAME;
    public static final UnsupportedAttributePolicy DEFAULT_POLICY = UnsupportedAttributePolicy.Warn;

    public static class Builder extends AbstractSftpEventListenerManager implements ObjectBuilder<SftpSubsystemFactory> {
        private ExecutorService executors;
        private boolean shutdownExecutor;
        private UnsupportedAttributePolicy policy = DEFAULT_POLICY;

        public Builder() {
            super();
        }

        public Builder withExecutorService(ExecutorService service) {
            executors = service;
            return this;
        }

        public Builder withShutdownOnExit(boolean shutdown) {
            shutdownExecutor = shutdown;
            return this;
        }

        public Builder withUnsupportedAttributePolicy(UnsupportedAttributePolicy p) {
            policy = ValidateUtils.checkNotNull(p, "No policy");
            return this;
        }

        @Override
        public SftpSubsystemFactory build() {
            SftpSubsystemFactory factory = new SftpSubsystemFactory();
            factory.setExecutorService(executors);
            factory.setShutdownOnExit(shutdownExecutor);
            factory.setUnsupportedAttributePolicy(policy);

            Collection<? extends SftpEventListener> listeners = getRegisteredListeners();
            if (GenericUtils.size(listeners) > 0) {
                for (SftpEventListener l : listeners) {
                    factory.addSftpEventListener(l);
                }
            }

            return factory;
        }
    }

    private ExecutorService executors;
    private boolean shutdownExecutor;
    private UnsupportedAttributePolicy policy = DEFAULT_POLICY;

    public SftpSubsystemFactory() {
        super();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executors;
    }

    /**
     * @param service The {@link ExecutorService} to be used by the {@link SftpSubsystem}
     *                command when starting execution. If {@code null} then a single-threaded ad-hoc service is used.
     */
    @Override
    public void setExecutorService(ExecutorService service) {
        executors = service;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownExecutor;
    }

    /**
     * @param shutdownOnExit If {@code true} the {@link ExecutorService#shutdownNow()}
     *                       will be called when subsystem terminates - unless it is the ad-hoc service, which
     *                       will be shutdown regardless
     */
    @Override
    public void setShutdownOnExit(boolean shutdownOnExit) {
        shutdownExecutor = shutdownOnExit;
    }

    public UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return policy;
    }

    /**
     * @param p The {@link UnsupportedAttributePolicy} to use if failed to access
     *          some local file attributes - never {@code null}
     */
    public void setUnsupportedAttributePolicy(UnsupportedAttributePolicy p) {
        policy = ValidateUtils.checkNotNull(p, "No policy");
    }

    @Override
    public Command create() {
        SftpSubsystem subsystem = new SftpSubsystem(getExecutorService(), isShutdownOnExit(), getUnsupportedAttributePolicy());
        Collection<? extends SftpEventListener> listeners = getRegisteredListeners();
        if (GenericUtils.size(listeners) > 0) {
            for (SftpEventListener l : listeners) {
                subsystem.addSftpEventListener(l);
            }
        }

        return subsystem;
    }
}
