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

package org.apache.sshd.sftp.client.fs;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.auth.BasicCredentialsProvider;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpFileSystemInitializationContext {
    private final String id;
    private final URI uri;
    private final Map<String, ?> environment;
    private String host;
    private int port;
    private BasicCredentialsProvider credentials;
    private PropertyResolver propertyResolver;
    private Duration maxConnectTime;
    private Duration maxAuthTime;

    /**
     * @param id  The unique identifier assigned to the file-system being created
     * @param uri The original {@link URI} that triggered the file-system creation
     * @param env The environment settings passed along with the URI (may be {@code null})
     */
    public SftpFileSystemInitializationContext(String id, URI uri, Map<String, ?> env) {
        this.id = id;
        this.uri = uri;
        this.environment = env;
    }

    /**
     * @return The unique identifier assigned to the file-system being created
     */
    public String getId() {
        return id;
    }

    /**
     * @return The original {@link URI} that triggered the file-system creation
     */
    public URI getUri() {
        return uri;
    }

    /**
     * @return The environment settings passed along with the URI (may be {@code null})
     */
    public Map<String, ?> getEnvironment() {
        return environment;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    /**
     * @return The <U>resolved</U> target port from the URI
     */
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    /**
     * @return The credentials recovered from the URI
     */
    public BasicCredentialsProvider getCredentials() {
        return credentials;
    }

    public void setCredentials(BasicCredentialsProvider credentials) {
        this.credentials = credentials;
    }

    /**
     * @return A {@link PropertyResolver} for easy access of any query parameters encoded in the URI
     */
    public PropertyResolver getPropertyResolver() {
        return propertyResolver;
    }

    public void setPropertyResolver(PropertyResolver propertyResolver) {
        this.propertyResolver = propertyResolver;
    }

    /**
     * @return The <U>resolved</U> max. connect timeout (msec.)
     */
    public Duration getMaxConnectTime() {
        return maxConnectTime;
    }

    public void setMaxConnectTime(Duration maxConnectTime) {
        this.maxConnectTime = maxConnectTime;
    }

    /**
     * @return The <U>resolved</U> max. authentication timeout (msec.)
     */
    public Duration getMaxAuthTime() {
        return maxAuthTime;
    }

    public void setMaxAuthTime(Duration maxAuthTime) {
        this.maxAuthTime = maxAuthTime;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getId() + "]";
    }
}
