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
package org.apache.sshd.client.session.proxy;

/**
 * A very simple representation of a HTTP status line.
 */
public class StatusLine {

    private final String version;

    private final int resultCode;

    private final String reason;

    /**
     * Create a new {@link StatusLine} with the given response code and reason string.
     *
     * @param version    the version string (normally "HTTP/1.1" or "HTTP/1.0")
     * @param resultCode the HTTP response code (200, 401, etc.)
     * @param reason     the reason phrase for the code
     */
    public StatusLine(String version, int resultCode, String reason) {
        this.version = version;
        this.resultCode = resultCode;
        this.reason = reason;
    }

    /**
     * Retrieves the version string.
     *
     * @return the version string
     */
    public String getVersion() {
        return version;
    }

    /**
     * Retrieves the HTTP response code.
     *
     * @return the code
     */
    public int getResultCode() {
        return resultCode;
    }

    /**
     * Retrieves the HTTP reason phrase.
     *
     * @return the reason
     */
    public String getReason() {
        return reason;
    }
}
