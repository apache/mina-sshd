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

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import javax.security.auth.login.FailedLoginException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface FilePasswordProvider {
    enum ResourceDecodeResult {
        /** Re-throw the decoding exception */
        TERMINATE,
        /** Try again the decoding process - including password prompt */
        RETRY,
        /** Skip attempt and see if can proceed without the key */
        IGNORE;

        public static final Set<ResourceDecodeResult> VALUES
                = Collections.unmodifiableSet(EnumSet.allOf(ResourceDecodeResult.class));
    }

    /**
     * An &quot;empty&quot; provider that returns {@code null} - i.e., unprotected key file
     */
    FilePasswordProvider EMPTY = (session, resourceKey, retryIndex) -> null;

    /**
     * @param  session     The {@link SessionContext} for invoking this load command - may be {@code null} if not
     *                     invoked within a session context (e.g., offline tool or session unknown).
     * @param  resourceKey The resource key representing the <U>private</U> file
     * @param  retryIndex  The zero-based index of the invocation for the specific resource (in case invoked several
     *                     times for the same resource)
     * @return             The password - if {@code null}/empty then no password is required
     * @throws IOException if cannot resolve password
     * @see                #handleDecodeAttemptResult(SessionContext, NamedResource, int, String, Exception)
     */
    String getPassword(SessionContext session, NamedResource resourceKey, int retryIndex) throws IOException;

    /**
     * Invoked to inform the password provide about the decoding result. <b>Note:</b> any exception thrown from this
     * method (including if called to inform about success) will be propagated instead of the original (if any was
     * reported)
     *
     * @param  session                  The {@link SessionContext} for invoking this load command - may be {@code null}
     *                                  if not invoked within a session context (e.g., offline tool or session unknown).
     * @param  resourceKey              The resource key representing the <U>private</U> file
     * @param  retryIndex               The zero-based index of the invocation for the specific resource (in case
     *                                  invoked several times for the same resource). If success report, it indicates
     *                                  the number of retries it took to succeed
     * @param  password                 The password that was attempted
     * @param  err                      The attempt result - {@code null} for success
     * @return                          How to proceed in case of error - <u>ignored</u> if invoked in order to report
     *                                  success. <b>Note:</b> {@code null} is same as
     *                                  {@link ResourceDecodeResult#TERMINATE}.
     * @throws IOException              If cannot resolve a new password
     * @throws GeneralSecurityException If not attempting to resolve a new password
     */
    default ResourceDecodeResult handleDecodeAttemptResult(
            SessionContext session, NamedResource resourceKey, int retryIndex, String password, Exception err)
            throws IOException, GeneralSecurityException {
        return ResourceDecodeResult.TERMINATE;
    }

    /**
     * Something that can produce a result given a password.
     *
     * @param <T> type of the result
     */
    interface Decoder<T> {
        T decode(String password) throws IOException, GeneralSecurityException;
    }

    /**
     * Obtains the password through {@link #getPassword(SessionContext, NamedResource, int)}, invokes the
     * {@link Decoder} and then
     * {@link #handleDecodeAttemptResult(SessionContext, NamedResource, int, String, Exception)} and then returns the
     * decoded result. If the decoder fails and the {@link ResourceDecodeResult} is {@link ResourceDecodeResult#RETRY},
     * the whole process is re-tried.
     *
     * @param  <T>                      Result type of the decoder
     * @param  session                  {@link SessionContext}, may be {@code null}
     * @param  resourceKey              {@link NamedResource} used for error reporting
     * @param  decoder                  {@link Decoder} to produce the result given a password
     * @return                          the decoder's result, or {@code null} if none
     * @throws IOException              if an I/O problem occurs
     * @throws GeneralSecurityException if the decoder throws it
     */
    default <T> T decode(SessionContext session, NamedResource resourceKey, Decoder<? extends T> decoder)
            throws IOException, GeneralSecurityException {
        for (int retryCount = 0;; retryCount++) {
            String pwd = getPassword(session, resourceKey, retryCount);
            if (GenericUtils.isEmpty(pwd)) {
                throw new FailedLoginException("No password data for encrypted resource=" + resourceKey);
            }
            try {
                T result = decoder.decode(pwd);
                handleDecodeAttemptResult(session, resourceKey, retryCount, pwd, null);
                return result;
            } catch (IOException | GeneralSecurityException | RuntimeException e) {
                ResourceDecodeResult result = handleDecodeAttemptResult(session, resourceKey, retryCount, pwd, e);
                if (result == null) {
                    throw e;
                }
                switch (result) {
                    case TERMINATE:
                        throw e;
                    case RETRY:
                        continue;
                    case IGNORE:
                        return null;
                    default:
                        throw new ProtocolException("Unsupported decode attempt result (" + result + ") for " + resourceKey);
                }
            }
        }
    }

    static FilePasswordProvider of(String password) {
        return (session, resource, index) -> password;
    }
}
