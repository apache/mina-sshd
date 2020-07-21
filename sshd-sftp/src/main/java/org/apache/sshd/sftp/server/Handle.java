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
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class Handle implements java.nio.channels.Channel, AttributeStore {
    private final SftpSubsystem sftpSubsystem;
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final Path file;
    private final String handle;
    private final Map<AttributeRepository.AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();

    protected Handle(SftpSubsystem subsystem, Path file, String handle) {
        this.sftpSubsystem = Objects.requireNonNull(subsystem, "No subsystem instance provided");
        this.file = Objects.requireNonNull(file, "No local file path");
        this.handle = ValidateUtils.checkNotNullAndNotEmpty(handle, "No assigned handle for %s", file);
    }

    protected SftpSubsystem getSubsystem() {
        return sftpSubsystem;
    }

    protected void signalHandleOpening() throws IOException {
        SftpSubsystem subsystem = getSubsystem();
        SftpEventListener listener = subsystem.getSftpEventListenerProxy();
        ServerSession session = subsystem.getServerSession();
        listener.opening(session, handle, this);
    }

    protected void signalHandleOpen() throws IOException {
        SftpSubsystem subsystem = getSubsystem();
        SftpEventListener listener = subsystem.getSftpEventListenerProxy();
        ServerSession session = subsystem.getServerSession();
        listener.open(session, handle, this);
    }

    public Path getFile() {
        return file;
    }

    public String getFileHandle() {
        return handle;
    }

    @Override
    public int getAttributesCount() {
        return attributes.size();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(AttributeRepository.AttributeKey<T> key) {
        return (T) attributes.get(Objects.requireNonNull(key, "No key"));
    }

    @Override
    public Collection<AttributeKey<?>> attributeKeys() {
        return attributes.isEmpty() ? Collections.emptySet() : new HashSet<>(attributes.keySet());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public <T> T computeAttributeIfAbsent(
            AttributeRepository.AttributeKey<T> key,
            Function<? super AttributeRepository.AttributeKey<T>, ? extends T> resolver) {
        return (T) attributes.computeIfAbsent(Objects.requireNonNull(key, "No key"), (Function) resolver);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T setAttribute(AttributeRepository.AttributeKey<T> key, T value) {
        return (T) attributes.put(
                Objects.requireNonNull(key, "No key"),
                Objects.requireNonNull(value, "No value"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T removeAttribute(AttributeRepository.AttributeKey<T> key) {
        return (T) attributes.remove(Objects.requireNonNull(key, "No key"));
    }

    @Override
    public void clearAttributes() {
        attributes.clear();
    }

    @Override
    public boolean isOpen() {
        return !closed.get();
    }

    @Override
    public void close() throws IOException {
        if (!closed.getAndSet(true)) {
            // noinspection UnnecessaryReturnStatement
            return; // debug breakpoint
        }
    }

    @Override
    public String toString() {
        return Objects.toString(getFile());
    }
}
