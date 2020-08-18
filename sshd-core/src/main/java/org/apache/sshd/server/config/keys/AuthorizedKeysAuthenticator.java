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

package org.apache.sshd.server.config.keys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.io.ModifiableFileWatcher;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 * Uses the authorized keys file to implement {@link PublickeyAuthenticator} while automatically re-loading the keys if
 * the file has changed when a new authentication request is received. <B>Note:</B> by default, the only validation of
 * the username is that it is not {@code null}/empty - see {@link #isValidUsername(String, ServerSession)}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AuthorizedKeysAuthenticator extends ModifiableFileWatcher implements PublickeyAuthenticator {
    /**
     * Standard OpenSSH authorized keys file name
     */
    public static final String STD_AUTHORIZED_KEYS_FILENAME = "authorized_keys";

    private static final class LazyDefaultAuthorizedKeysFileHolder {
        private static final Path KEYS_FILE = PublicKeyEntry.getDefaultKeysFolderPath().resolve(STD_AUTHORIZED_KEYS_FILENAME);

        private LazyDefaultAuthorizedKeysFileHolder() {
            throw new UnsupportedOperationException("No instance allowed");
        }
    }

    private final AtomicReference<PublickeyAuthenticator> delegateHolder = // assumes initially reject-all
            new AtomicReference<>(RejectAllPublickeyAuthenticator.INSTANCE);

    public AuthorizedKeysAuthenticator(Path file) {
        this(file, IoUtils.getLinkOptions(false));
    }

    public AuthorizedKeysAuthenticator(Path file, LinkOption... options) {
        super(file, options);
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        boolean debugEnabled = log.isDebugEnabled();
        if (!isValidUsername(username, session)) {
            if (debugEnabled) {
                log.debug("authenticate({})[{}][{}] invalid user name - file = {}",
                        username, session, key.getAlgorithm(), getPath());
            }
            return false;
        }

        try {
            PublickeyAuthenticator delegate
                    = Objects.requireNonNull(resolvePublickeyAuthenticator(username, session), "No delegate");
            boolean accepted = delegate.authenticate(username, key, session);
            if (debugEnabled) {
                log.debug("authenticate({})[{}][{}] invalid user name - accepted={} from file = {}",
                        username, session, key.getAlgorithm(), accepted, getPath());
            }

            return accepted;
        } catch (Throwable e) {
            debug("authenticate({})[{}] failed ({}) to authenticate {} key from {}: {}",
                    username, session, e.getClass().getSimpleName(), key.getAlgorithm(), getPath(), e.getMessage(), e);
            return false;
        }
    }

    protected boolean isValidUsername(String username, ServerSession session) {
        return GenericUtils.isNotEmpty(username);
    }

    protected PublickeyAuthenticator resolvePublickeyAuthenticator(String username, ServerSession session)
            throws IOException, GeneralSecurityException {
        if (checkReloadRequired()) {
            /*
             * Start fresh - NOTE: if there is any error then we want to reject all attempts since we don't want to
             * remain with the previous data - safer that way
             */
            delegateHolder.set(RejectAllPublickeyAuthenticator.INSTANCE);

            Path path = getPath();
            if (exists()) {
                Collection<AuthorizedKeyEntry> entries = reloadAuthorizedKeys(path, username, session);
                if (GenericUtils.size(entries) > 0) {
                    PublickeyAuthenticator authDelegate = createDelegateAuthenticator(username, session, path, entries,
                            getFallbackPublicKeyEntryResolver());
                    delegateHolder.set(authDelegate);
                }
            } else {
                log.info("resolvePublickeyAuthenticator({})[{}] no authorized keys file at {}", username, session, path);
            }
        }

        return delegateHolder.get();
    }

    protected PublickeyAuthenticator createDelegateAuthenticator(
            String username, ServerSession session, Path path,
            Collection<AuthorizedKeyEntry> entries, PublicKeyEntryResolver fallbackResolver)
            throws IOException, GeneralSecurityException {
        return PublickeyAuthenticator.fromAuthorizedEntries(path, session, entries, fallbackResolver);
    }

    protected PublicKeyEntryResolver getFallbackPublicKeyEntryResolver() {
        return PublicKeyEntryResolver.IGNORING;
    }

    protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(
            Path path, String username, ServerSession session)
            throws IOException, GeneralSecurityException {
        Collection<AuthorizedKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(path);
        log.info("reloadAuthorizedKeys({})[{}] loaded {} keys from {}",
                username, session, GenericUtils.size(entries), path);
        updateReloadAttributes();
        return entries;
    }

    /**
     * @return The default {@link Path} location of the OpenSSH authorized keys file
     */
    @SuppressWarnings("synthetic-access")
    public static Path getDefaultAuthorizedKeysFile() {
        return LazyDefaultAuthorizedKeysFileHolder.KEYS_FILE;
    }

    /**
     * Reads read the contents of the default OpenSSH <code>authorized_keys</code> file
     *
     * @param  options     The {@link OpenOption}s to use when reading the file
     * @return             A {@link List} of all the {@link AuthorizedKeyEntry}-ies found there - or empty if file does
     *                     not exist
     * @throws IOException If failed to read keys from file
     */
    public static List<AuthorizedKeyEntry> readDefaultAuthorizedKeys(OpenOption... options) throws IOException {
        Path keysFile = getDefaultAuthorizedKeysFile();
        if (Files.exists(keysFile, IoUtils.EMPTY_LINK_OPTIONS)) {
            return AuthorizedKeyEntry.readAuthorizedKeys(keysFile);
        } else {
            return Collections.emptyList();
        }
    }
}
