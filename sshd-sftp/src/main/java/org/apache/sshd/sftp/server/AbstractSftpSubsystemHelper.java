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

import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.CopyOption;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.Principal;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.IntUnaryOperator;

import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.OptionalFeature;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.config.VersionProperties;
import org.apache.sshd.common.digest.BuiltinDigests;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils.NavigableMapBuilder;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.FileInfoExtractor;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.sftp.SftpModuleProperties;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.common.SftpHelper;
import org.apache.sshd.sftp.common.extensions.AclSupportedParser;
import org.apache.sshd.sftp.common.extensions.SpaceAvailableExtensionInfo;
import org.apache.sshd.sftp.common.extensions.openssh.AbstractOpenSSHExtensionParser.OpenSSHExtension;
import org.apache.sshd.sftp.common.extensions.openssh.FsyncExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.HardLinkExtensionParser;
import org.apache.sshd.sftp.common.extensions.openssh.LSetStatExtensionParser;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@SuppressWarnings("checkstyle:MethodCount") // TODO split this big class and remove the suppression
public abstract class AbstractSftpSubsystemHelper
        extends AbstractLoggingBean
        implements SftpSubsystemProxy {

    /**
     * The default reported supported client extensions (case <U>insensitive</U>)
     */
    public static final NavigableMap<String, OptionalFeature> DEFAULT_SUPPORTED_CLIENT_EXTENSIONS =
    // TODO text-seek - see http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-13.txt
    // TODO home-directory - see
    // http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
            NavigableMapBuilder.<String, OptionalFeature> builder()
                    .put(SftpConstants.EXT_VERSION_SELECT, OptionalFeature.TRUE)
                    .put(SftpConstants.EXT_COPY_FILE, OptionalFeature.TRUE)
                    .put(SftpConstants.EXT_MD5_HASH, BuiltinDigests.md5)
                    .put(SftpConstants.EXT_MD5_HASH_HANDLE, BuiltinDigests.md5)
                    .put(SftpConstants.EXT_CHECK_FILE_HANDLE, OptionalFeature.any(BuiltinDigests.VALUES))
                    .put(SftpConstants.EXT_CHECK_FILE_NAME, OptionalFeature.any(BuiltinDigests.VALUES))
                    .put(SftpConstants.EXT_COPY_DATA, OptionalFeature.TRUE)
                    .put(SftpConstants.EXT_SPACE_AVAILABLE, OptionalFeature.TRUE)
                    .immutable();

    public static final List<OpenSSHExtension> DEFAULT_OPEN_SSH_EXTENSIONS = Collections.unmodifiableList(
            Arrays.asList(
                    new OpenSSHExtension(FsyncExtensionParser.NAME, "1"),
                    new OpenSSHExtension(HardLinkExtensionParser.NAME, "1"),
                    new OpenSSHExtension(LSetStatExtensionParser.NAME, "1")));

    public static final List<String> DEFAULT_OPEN_SSH_EXTENSIONS_NAMES = Collections.unmodifiableList(
            NamedResource.getNameList(DEFAULT_OPEN_SSH_EXTENSIONS));

    public static final Set<Integer> DEFAULT_ACL_SUPPORTED_MASK = Collections.unmodifiableSet(
            new HashSet<>(
                    Arrays.asList(
                            SftpConstants.SSH_ACL_CAP_ALLOW,
                            SftpConstants.SSH_ACL_CAP_DENY,
                            SftpConstants.SSH_ACL_CAP_AUDIT,
                            SftpConstants.SSH_ACL_CAP_ALARM)));

    private final UnsupportedAttributePolicy unsupportedAttributePolicy;
    private final Collection<SftpEventListener> sftpEventListeners = new CopyOnWriteArraySet<>();
    private final SftpEventListener sftpEventListenerProxy;
    private final SftpFileSystemAccessor fileSystemAccessor;
    private final SftpErrorStatusDataHandler errorStatusDataHandler;

    protected AbstractSftpSubsystemHelper(
                                          UnsupportedAttributePolicy policy, SftpFileSystemAccessor accessor,
                                          SftpErrorStatusDataHandler handler) {
        unsupportedAttributePolicy = Objects.requireNonNull(policy, "No unsupported attribute policy provided");
        fileSystemAccessor = Objects.requireNonNull(accessor, "No file system accessor");
        sftpEventListenerProxy = EventListenerUtils.proxyWrapper(SftpEventListener.class, sftpEventListeners);
        errorStatusDataHandler = Objects.requireNonNull(handler, "No error status data handler");
    }

    @Override
    public UnsupportedAttributePolicy getUnsupportedAttributePolicy() {
        return unsupportedAttributePolicy;
    }

    @Override
    public SftpFileSystemAccessor getFileSystemAccessor() {
        return fileSystemAccessor;
    }

    @Override
    public SftpEventListener getSftpEventListenerProxy() {
        return sftpEventListenerProxy;
    }

    @Override
    public boolean addSftpEventListener(SftpEventListener listener) {
        return sftpEventListeners.add(SftpEventListener.validateListener(listener));
    }

    @Override
    public boolean removeSftpEventListener(SftpEventListener listener) {
        if (listener == null) {
            return false;
        }

        return sftpEventListeners.remove(SftpEventListener.validateListener(listener));
    }

    public SftpErrorStatusDataHandler getErrorStatusDataHandler() {
        return errorStatusDataHandler;
    }

    /**
     * @param  buffer      The {@link Buffer} holding the request
     * @param  id          The request id
     * @param  proposal    The proposed value
     * @return             A {@link Boolean} indicating whether to accept/reject the proposal. If {@code null} then
     *                     rejection response has been sent, otherwise and appropriate response is generated
     * @throws IOException If failed send an independent rejection response
     */
    protected Boolean validateProposedVersion(Buffer buffer, int id, String proposal) throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        Session session = getServerSession();
        if (debugEnabled) {
            log.debug("validateProposedVersion({})[id={}] SSH_FXP_EXTENDED(version-select) (version={})",
                    session, id, proposal);
        }

        if (GenericUtils.length(proposal) != 1) {
            return Boolean.FALSE;
        }

        char digit = proposal.charAt(0);
        if ((digit < '0') || (digit > '9')) {
            return Boolean.FALSE;
        }

        int proposed = digit - '0';
        Map.Entry<Integer, String> result = checkVersionCompatibility(buffer, id, proposed, SftpConstants.SSH_FX_FAILURE);
        if (result == null) { // validation failed
            return null;
        }

        int negotiated = result.getKey();
        if (negotiated != proposed) {
            if (debugEnabled) {
                log.debug(
                        "validateProposedVersion({})[id={}] SSH_FXP_EXTENDED(version-select) proposed={} different than negotiated={}",
                        session, id, proposed, negotiated);
            }
            return Boolean.FALSE;
        } else {
            return Boolean.TRUE;
        }
    }

    /**
     * Checks if a proposed version is within supported range. <B>Note:</B> if the user forced a specific value via the
     * {@link SftpModuleProperties#SFTP_VERSION} property, then it is used to validate the proposed value
     *
     * @param  buffer        The {@link Buffer} containing the request
     * @param  id            The SSH message ID to be used to send the failure message if required
     * @param  proposed      The proposed version value
     * @param  failureOpcode The failure opcode to send if validation fails
     * @return               A &quot;pair&quot; whose key is the negotiated version and value a {@link String} of comma
     *                       separated values representing all the supported versions. {@code null} if validation failed
     *                       and an appropriate status message was sent
     * @throws IOException   If failed to send the failure status message
     */
    protected Map.Entry<Integer, String> checkVersionCompatibility(
            Buffer buffer, int id, int proposed, int failureOpcode)
            throws IOException {
        int low = SftpSubsystemEnvironment.LOWER_SFTP_IMPL;
        int hig = SftpSubsystemEnvironment.HIGHER_SFTP_IMPL;
        String available = SftpSubsystemEnvironment.ALL_SFTP_IMPL;
        // check if user wants to use a specific version
        ServerSession session = getServerSession();
        Integer sftpVersion = SftpModuleProperties.SFTP_VERSION.getOrNull(session);
        if (sftpVersion != null) {
            int forcedValue = sftpVersion;
            if ((forcedValue < SftpSubsystemEnvironment.LOWER_SFTP_IMPL)
                    || (forcedValue > SftpSubsystemEnvironment.HIGHER_SFTP_IMPL)) {
                throw new IllegalStateException(
                        "Forced SFTP version (" + sftpVersion + ") not within supported values: " + available);
            }
            hig = sftpVersion;
            low = hig;
            available = sftpVersion.toString();
        }

        boolean traceEnabled = log.isTraceEnabled();
        if (traceEnabled) {
            log.trace("checkVersionCompatibility({})[id={}] - proposed={}, available={}",
                    session, id, proposed, available);
        }

        /*
         * According to all drafts, the server responds with a SSH_FXP_VERSION packet, supplying the lowest (!) of its
         * own and the client's version number. However, if the client is below what we can support it makes no sense to
         * agree to it.
         */
        if (proposed < low) {
            sendStatus(prepareReply(buffer), id, failureOpcode,
                    "Proposed version (" + proposed + ") not in supported range: " + available);
            return null;
        }

        // Force the client to use a lower protocol
        if (proposed > hig) {
            if (traceEnabled) {
                log.trace("checkVersionCompatibility({})[id={}] - replace proposed={} with negotiated={} due to available={}",
                        session, id, proposed, hig, available);
            }
            proposed = hig; // debug breakpoint
        }

        return new SimpleImmutableEntry<>(proposed, available);
    }

    /**
     * Process an SFTP command. If the command throws an exception, the channel will be closed.
     *
     * @param  buffer      the buffer to process
     * @throws IOException if anything wrong happens
     */
    protected void process(Buffer buffer) throws IOException {
        int length = buffer.getInt();
        int type = buffer.getUByte();
        int id = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("process({})[length={}, type={}, id={}] processing",
                    getServerSession(), length, SftpConstants.getCommandMessageName(type), id);
        }
        try {
            SftpEventListener listener = getSftpEventListenerProxy();
            ServerSession session = getServerSession();
            listener.received(session, type, id);
        } catch (IOException | RuntimeException e) {
            if (type == SftpConstants.SSH_FXP_INIT) {
                throw e;
            }
            sendStatus(prepareReply(buffer), id, e, type);
            return;
        }
        doProcess(buffer, length, type, id);
    }

    protected void doProcess(Buffer buffer, int length, int type, int id) throws IOException {
        switch (type) {
            case SftpConstants.SSH_FXP_INIT:
                doInit(buffer, id);
                break;
            case SftpConstants.SSH_FXP_OPEN:
                doOpen(buffer, id);
                break;
            case SftpConstants.SSH_FXP_CLOSE:
                doClose(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READ:
                doRead(buffer, id);
                break;
            case SftpConstants.SSH_FXP_WRITE:
                doWrite(buffer, id);
                break;
            case SftpConstants.SSH_FXP_LSTAT:
                doLStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_FSTAT:
                doFStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_SETSTAT:
                doSetStat(buffer, id, "", type, null);
                break;
            case SftpConstants.SSH_FXP_FSETSTAT:
                doFSetStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_OPENDIR:
                doOpenDir(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READDIR:
                doReadDir(buffer, id);
                break;
            case SftpConstants.SSH_FXP_REMOVE:
                doRemove(buffer, id);
                break;
            case SftpConstants.SSH_FXP_MKDIR:
                doMakeDirectory(buffer, id);
                break;
            case SftpConstants.SSH_FXP_RMDIR:
                doRemoveDirectory(buffer, id);
                break;
            case SftpConstants.SSH_FXP_REALPATH:
                doRealPath(buffer, id);
                break;
            case SftpConstants.SSH_FXP_STAT:
                doStat(buffer, id);
                break;
            case SftpConstants.SSH_FXP_RENAME:
                doRename(buffer, id);
                break;
            case SftpConstants.SSH_FXP_READLINK:
                doReadLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_SYMLINK:
                doSymLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_LINK:
                doLink(buffer, id);
                break;
            case SftpConstants.SSH_FXP_BLOCK:
                doBlock(buffer, id);
                break;
            case SftpConstants.SSH_FXP_UNBLOCK:
                doUnblock(buffer, id);
                break;
            case SftpConstants.SSH_FXP_EXTENDED:
                doExtended(buffer, id);
                break;
            default:
                doUnsupported(buffer, length, type, id);
                break;
        }
    }

    protected void doUnsupported(Buffer buffer, int length, int type, int id) throws IOException {
        String name = SftpConstants.getCommandMessageName(type);
        log.warn("process({})[length={}, type={}, id={}] unknown command",
                getServerSession(), length, name, id);
        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OP_UNSUPPORTED,
                "Command " + name + " is unsupported or not implemented");
    }

    protected abstract void doInit(Buffer buffer, int id) throws IOException;

    protected void doVersionSelect(Buffer buffer, int id) throws IOException {
        String proposed = buffer.getString();
        doVersionSelect(buffer, id, proposed);
    }

    protected abstract void doVersionSelect(Buffer buffer, int id, String proposed) throws IOException;

    protected void doOpen(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        /*
         * Be consistent with FileChannel#open - if no mode specified then READ is assumed
         */
        int access = 0;
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V5) {
            access = buffer.getInt();
            if (access == 0) {
                access = SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
            }
        }

        int pflags = buffer.getInt();
        if (pflags == 0) {
            pflags = SftpConstants.SSH_FXF_READ;
        }

        if (version < SftpConstants.SFTP_V5) {
            int flags = pflags;
            pflags = 0;
            switch (flags & (SftpConstants.SSH_FXF_READ | SftpConstants.SSH_FXF_WRITE)) {
                case SftpConstants.SSH_FXF_READ:
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                    break;
                case SftpConstants.SSH_FXF_WRITE:
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                    break;
                default:
                    access |= SftpConstants.ACE4_READ_DATA | SftpConstants.ACE4_READ_ATTRIBUTES;
                    access |= SftpConstants.ACE4_WRITE_DATA | SftpConstants.ACE4_WRITE_ATTRIBUTES;
                    break;
            }
            if ((flags & SftpConstants.SSH_FXF_APPEND) != 0) {
                access |= SftpConstants.ACE4_APPEND_DATA;
                pflags |= SftpConstants.SSH_FXF_APPEND_DATA | SftpConstants.SSH_FXF_APPEND_DATA_ATOMIC;
            }
            if ((flags & SftpConstants.SSH_FXF_CREAT) != 0) {
                if ((flags & SftpConstants.SSH_FXF_EXCL) != 0) {
                    pflags |= SftpConstants.SSH_FXF_CREATE_NEW;
                } else if ((flags & SftpConstants.SSH_FXF_TRUNC) != 0) {
                    pflags |= SftpConstants.SSH_FXF_CREATE_TRUNCATE;
                } else {
                    pflags |= SftpConstants.SSH_FXF_OPEN_OR_CREATE;
                }
            } else {
                if ((flags & SftpConstants.SSH_FXF_TRUNC) != 0) {
                    pflags |= SftpConstants.SSH_FXF_TRUNCATE_EXISTING;
                } else {
                    pflags |= SftpConstants.SSH_FXF_OPEN_EXISTING;
                }
            }
        }

        Map<String, Object> attrs = readAttrs(buffer);
        String handle;
        try {
            handle = doOpen(id, path, pflags, access, attrs);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_OPEN, path);
            return;
        }

        sendHandle(prepareReply(buffer), id, handle);
    }

    /**
     * @param  id          Request id
     * @param  path        Path
     * @param  pflags      Open mode flags - see {@code SSH_FXF_XXX} flags
     * @param  access      Access mode flags - see {@code ACE4_XXX} flags
     * @param  attrs       Requested attributes
     * @return             The assigned (opaque) handle
     * @throws IOException if failed to execute
     */
    protected abstract String doOpen(
            int id, String path, int pflags, int access, Map<String, Object> attrs)
            throws IOException;

    protected <E extends IOException> E signalOpenFailure(
            int id, String pathValue, Path path, boolean isDir, E thrown)
            throws IOException {
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("signalOpenFailure(id={})[{}] signal {} for {}: {}",
                    id, pathValue, thrown.getClass().getSimpleName(), path, thrown.getMessage());
        }

        listener.openFailed(session, pathValue, path, isDir, thrown);
        return thrown;
    }

    protected void doClose(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        try {
            doClose(id, handle);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_CLOSE, handle);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "", "");
    }

    protected abstract void doClose(int id, String handle) throws IOException;

    protected void doRead(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int requestedLength = buffer.getInt();
        ServerSession session = getServerSession();
        int maxAllowed = SftpModuleProperties.MAX_READDATA_PACKET_LENGTH.getRequired(session);
        int readLen = Math.min(requestedLength, maxAllowed);
        if (log.isTraceEnabled()) {
            log.trace("doRead({})[id={}]({})[offset={}] - req={}, max={}, effective={}",
                    session, id, handle, offset, requestedLength, maxAllowed, readLen);
        }

        try {
            ValidateUtils.checkTrue(readLen >= 0, "Illegal requested read length: %d", readLen);

            buffer = prepareReply(buffer);
            buffer.ensureCapacity(readLen + Long.SIZE /* the header */, IntUnaryOperator.identity());

            buffer.putByte((byte) SftpConstants.SSH_FXP_DATA);
            buffer.putInt(id);
            int lenPos = buffer.wpos();
            buffer.putInt(0);

            int startPos = buffer.wpos();
            int len = doRead(id, handle, offset, readLen, buffer.array(), startPos);
            if (len < 0) {
                throw new EOFException("Unable to read " + readLen + " bytes from offset=" + offset + " of " + handle);
            }
            buffer.wpos(startPos + len);
            BufferUtils.updateLengthPlaceholder(buffer, lenPos, len);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_READ, handle, offset, requestedLength);
            return;
        }

        send(buffer);
    }

    protected abstract int doRead(
            int id, String handle, long offset, int length, byte[] data, int doff)
            throws IOException;

    protected void doWrite(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        int length = buffer.getInt();
        try {
            doWrite(id, handle, offset, length, buffer.array(), buffer.rpos(), buffer.available());
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_WRITE, handle, offset, length);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doWrite(
            int id, String handle, long offset, int length, byte[] data, int doff, int remaining)
            throws IOException;

    protected void doLStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SftpConstants.SSH_FILEXFER_ATTR_ALL;
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String, ?> attrs;
        try {
            attrs = doLStat(id, path, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_LSTAT, path, flags);
            return;
        }

        sendAttrs(prepareReply(buffer), id, attrs);
    }

    protected Map<String, Object> doLStat(int id, String path, int flags) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doLStat({})[id={}] SSH_FXP_LSTAT (path={}[{}], flags=0x{})",
                    getServerSession(), id, path, p, Integer.toHexString(flags));
        }

        /*
         * SSH_FXP_STAT and SSH_FXP_LSTAT only differ in that SSH_FXP_STAT follows symbolic links on the server, whereas
         * SSH_FXP_LSTAT does not.
         */
        return resolveFileAttributes(p, flags, IoUtils.getLinkOptions(false));
    }

    protected void doSetStat(
            Buffer buffer, int id, String extension, int cmd, Boolean followLinks /* null = auto-resolve */)
            throws IOException {
        String path = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        try {
            doSetStat(id, path, cmd, extension, attrs, followLinks);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_SETSTAT, path);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doSetStat(
            int id, String path, int cmd, String extension, Map<String, ?> attrs, Boolean followLinks /*
                                                                                                       * null =
                                                                                                       * auto-resolve
                                                                                                       */)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doSetStat({})[id={}, cmd={}, extension={}]  (path={}, attrs={}, followLinks={})",
                    getServerSession(), id, cmd, extension, path, attrs, followLinks);
        }

        Path p = resolveFile(path);
        if (followLinks == null) {
            followLinks = resolvePathResolutionFollowLinks(cmd, extension, p);
        }
        doSetAttributes(p, attrs, followLinks);
    }

    protected void doFStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        int flags = SftpConstants.SSH_FILEXFER_ATTR_ALL;
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String, ?> attrs;
        try {
            attrs = doFStat(id, handle, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_FSTAT, handle, flags);
            return;
        }

        sendAttrs(prepareReply(buffer), id, attrs);
    }

    protected abstract Map<String, Object> doFStat(int id, String handle, int flags) throws IOException;

    protected void doFSetStat(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        Map<String, Object> attrs = readAttrs(buffer);
        try {
            doFSetStat(id, handle, attrs);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_FSETSTAT, handle, attrs);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doFSetStat(int id, String handle, Map<String, ?> attrs) throws IOException;

    protected void doOpenDir(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        String handle;

        try {
            Path p = resolveNormalizedLocation(path);
            if (log.isDebugEnabled()) {
                log.debug("doOpenDir({})[id={}] SSH_FXP_OPENDIR (path={})[{}]",
                        getServerSession(), id, path, p);
            }

            LinkOption[] options = getPathResolutionLinkOption(SftpConstants.SSH_FXP_OPENDIR, "", p);
            handle = doOpenDir(id, path, p, options);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_OPENDIR, path);
            return;
        }

        sendHandle(prepareReply(buffer), id, handle);
    }

    protected abstract String doOpenDir(
            int id, String path, Path p, LinkOption... options)
            throws IOException;

    protected abstract void doReadDir(Buffer buffer, int id) throws IOException;

    protected void doLink(Buffer buffer, int id) throws IOException {
        String targetPath = buffer.getString();
        String linkPath = buffer.getString();
        boolean symLink = buffer.getBoolean();

        try {
            if (log.isDebugEnabled()) {
                log.debug("doLink({})[id={}] SSH_FXP_LINK linkpath={}, targetpath={}, symlink={}",
                        getServerSession(), id, linkPath, targetPath, symLink);
            }

            doLink(id, targetPath, linkPath, symLink);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_LINK, targetPath, linkPath, symLink);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doLink(int id, String targetPath, String linkPath, boolean symLink) throws IOException {
        createLink(id, targetPath, linkPath, symLink);
    }

    protected void doSymLink(Buffer buffer, int id) throws IOException {
        String targetPath = buffer.getString();
        String linkPath = buffer.getString();
        try {
            if (log.isDebugEnabled()) {
                log.debug("doSymLink({})[id={}] SSH_FXP_SYMLINK linkpath={}, targetpath={}",
                        getServerSession(), id, targetPath, linkPath);
            }
            doSymLink(id, targetPath, linkPath);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_SYMLINK, targetPath, linkPath);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doSymLink(int id, String targetPath, String linkPath) throws IOException {
        createLink(id, targetPath, linkPath, true);
    }

    protected abstract void createLink(
            int id, String existingPath, String linkPath, boolean symLink)
            throws IOException;

    // see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL section 10
    protected void doOpenSSHHardLink(Buffer buffer, int id) throws IOException {
        String srcFile = buffer.getString();
        String dstFile = buffer.getString();

        try {
            doOpenSSHHardLink(id, srcFile, dstFile);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_EXTENDED,
                    HardLinkExtensionParser.NAME, srcFile, dstFile);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doOpenSSHHardLink(int id, String srcFile, String dstFile) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doOpenSSHHardLink({})[id={}] SSH_FXP_EXTENDED[{}] (src={}, dst={})",
                    getServerSession(), id, HardLinkExtensionParser.NAME, srcFile, dstFile);
        }

        createLink(id, srcFile, dstFile, false);
    }

    protected void doSpaceAvailable(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        SpaceAvailableExtensionInfo info;
        try {
            info = doSpaceAvailable(id, path);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, SftpConstants.EXT_SPACE_AVAILABLE, path);
            return;
        }

        buffer = prepareReply(buffer);
        buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
        buffer.putInt(id);
        SpaceAvailableExtensionInfo.encode(buffer, info);
        send(buffer);
    }

    protected SpaceAvailableExtensionInfo doSpaceAvailable(int id, String path) throws IOException {
        Path nrm = resolveNormalizedLocation(path);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doSpaceAvailable({})[id={}] path={}[{}]", session, id, path, nrm);
        }

        FileStore store = Files.getFileStore(nrm);
        if (log.isTraceEnabled()) {
            log.trace("doSpaceAvailable({})[id={}] path={}[{}] - {}[{}]",
                    session, id, path, nrm, store.name(), store.type());
        }

        return new SpaceAvailableExtensionInfo(store);
    }

    protected void doTextSeek(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long line = buffer.getLong();
        try {
            // TODO : implement text-seek - see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-03#section-6.3
            doTextSeek(id, handle, line);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, SftpConstants.EXT_TEXT_SEEK, handle, line);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doTextSeek(int id, String handle, long line) throws IOException;

    // see https://github.com/openssh/openssh-portable/blob/master/PROTOCOL section 10
    protected void doOpenSSHFsync(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        try {
            doOpenSSHFsync(id, handle);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, FsyncExtensionParser.NAME, handle);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doOpenSSHFsync(int id, String handle) throws IOException;

    protected void doCheckFileHash(Buffer buffer, int id, String targetType) throws IOException {
        String target = buffer.getString();
        String algList = buffer.getString();
        String[] algos = GenericUtils.split(algList, ',');
        long startOffset = buffer.getLong();
        long length = buffer.getLong();
        int blockSize = buffer.getInt();
        try {
            buffer = prepareReply(buffer);
            buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
            buffer.putInt(id);
            buffer.putString(SftpConstants.EXT_CHECK_FILE);
            doCheckFileHash(id, targetType, target,
                    Arrays.asList(algos), startOffset, length, blockSize, buffer);
        } catch (Exception e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, targetType, target,
                    algList, startOffset, length, blockSize);
            return;
        }

        send(buffer);
    }

    protected void doCheckFileHash(
            int id, Path file, NamedFactory<? extends Digest> factory,
            long startOffset, long length, int blockSize, Buffer buffer)
            throws Exception {
        ValidateUtils.checkTrue(startOffset >= 0L, "Invalid start offset: %d", startOffset);
        ValidateUtils.checkTrue(length >= 0L, "Invalid length: %d", length);
        ValidateUtils.checkTrue(
                (blockSize == 0) || (blockSize >= SftpConstants.MIN_CHKFILE_BLOCKSIZE),
                "Invalid block size: %d", blockSize);
        Objects.requireNonNull(factory, "No digest factory provided");
        buffer.putString(factory.getName());

        long effectiveLength = length;
        long totalLength = Files.size(file);
        if (effectiveLength == 0L) {
            effectiveLength = totalLength - startOffset;
        } else {
            long maxRead = startOffset + length;
            if (maxRead > totalLength) {
                effectiveLength = totalLength - startOffset;
            }
        }
        ValidateUtils.checkTrue(effectiveLength > 0L,
                "Non-positive effective hash data length: %d", effectiveLength);

        byte[] digestBuf = (blockSize == 0)
                ? new byte[Math.min((int) effectiveLength, IoUtils.DEFAULT_COPY_SIZE)]
                : new byte[Math.min((int) effectiveLength, blockSize)];
        ByteBuffer wb = ByteBuffer.wrap(digestBuf);
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        ServerSession session = getServerSession();
        try (SeekableByteChannel channel = accessor.openFile(
                session, this, null, file, null, Collections.emptySet())) {
            channel.position(startOffset);

            Digest digest = factory.create();
            digest.init();

            boolean traceEnabled = log.isTraceEnabled();
            if (blockSize == 0) {
                while (effectiveLength > 0L) {
                    int remainLen = Math.min(digestBuf.length, (int) effectiveLength);
                    ByteBuffer bb = wb;
                    if (remainLen < digestBuf.length) {
                        bb = ByteBuffer.wrap(digestBuf, 0, remainLen);
                    }
                    bb.clear(); // prepare for next read

                    int readLen = channel.read(bb);
                    if (readLen < 0) {
                        break;
                    }

                    effectiveLength -= readLen;
                    digest.update(digestBuf, 0, readLen);
                }

                byte[] hashValue = digest.digest();
                if (traceEnabled) {
                    log.trace("doCheckFileHash({})[{}] offset={}, length={} - algo={}, hash={}",
                            session, file, startOffset, length,
                            digest.getAlgorithm(), BufferUtils.toHex(':', hashValue));
                }
                buffer.putBytes(hashValue);
            } else {
                for (int count = 0; effectiveLength > 0L; count++) {
                    int remainLen = Math.min(digestBuf.length, (int) effectiveLength);
                    ByteBuffer bb = wb;
                    if (remainLen < digestBuf.length) {
                        bb = ByteBuffer.wrap(digestBuf, 0, remainLen);
                    }
                    bb.clear(); // prepare for next read

                    int readLen = channel.read(bb);
                    if (readLen < 0) {
                        break;
                    }

                    effectiveLength -= readLen;
                    digest.update(digestBuf, 0, readLen);

                    byte[] hashValue = digest.digest(); // NOTE: this also resets the hash for the next read
                    if (traceEnabled) {
                        log.trace("doCheckFileHash({})({})[{}] offset={}, length={} - algo={}, hash={}",
                                session, file, count, startOffset, length,
                                digest.getAlgorithm(), BufferUtils.toHex(':', hashValue));
                    }
                    buffer.putBytes(hashValue);
                }
            }

            accessor.closeFile(session, this, null, file, null, channel, Collections.emptySet());
        }
    }

    protected void doMD5Hash(Buffer buffer, int id, String targetType) throws IOException {
        String target = buffer.getString();
        long startOffset = buffer.getLong();
        long length = buffer.getLong();
        byte[] quickCheckHash = buffer.getBytes();
        byte[] hashValue;

        try {
            hashValue = doMD5Hash(id, targetType, target, startOffset, length, quickCheckHash);
            if (log.isTraceEnabled()) {
                log.trace("doMD5Hash({})({})[{}] offset={}, length={}, quick-hash={} - hash={}",
                        getServerSession(), targetType, target, startOffset, length,
                        BufferUtils.toHex(':', quickCheckHash),
                        BufferUtils.toHex(':', hashValue));
            }

        } catch (Exception e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, targetType, target,
                    startOffset, length, quickCheckHash);
            return;
        }

        buffer = prepareReply(buffer);
        buffer.putByte((byte) SftpConstants.SSH_FXP_EXTENDED_REPLY);
        buffer.putInt(id);
        buffer.putString(targetType);
        buffer.putBytes(hashValue);
        send(buffer);
    }

    protected abstract byte[] doMD5Hash(
            int id, String targetType, String target, long startOffset, long length, byte[] quickCheckHash)
            throws Exception;

    protected byte[] doMD5Hash(
            int id, Path path, long startOffset, long length, byte[] quickCheckHash)
            throws Exception {
        ValidateUtils.checkTrue(startOffset >= 0L, "Invalid start offset: %d", startOffset);
        ValidateUtils.checkTrue(length > 0L, "Invalid length: %d", length);
        if (!BuiltinDigests.md5.isSupported()) {
            throw new UnsupportedOperationException(BuiltinDigests.md5.getAlgorithm() + " hash not supported");
        }

        Digest digest = BuiltinDigests.md5.create();
        digest.init();

        long effectiveLength = length;
        byte[] digestBuf = new byte[(int) Math.min(effectiveLength, SftpConstants.MD5_QUICK_HASH_SIZE)];
        ByteBuffer wb = ByteBuffer.wrap(digestBuf);
        boolean hashMatches = false;
        byte[] hashValue = null;
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        boolean traceEnabled = log.isTraceEnabled();
        ServerSession session = getServerSession();
        try (SeekableByteChannel channel = accessor.openFile(
                session, this, null, path, null, Collections.emptySet())) {
            channel.position(startOffset);

            /*
             * To quote http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt
             * section 9.1.1:
             *
             * If this is a zero length string, the client does not have the data, and is requesting the hash for
             * reasons other than comparing with a local file. The server MAY return SSH_FX_OP_UNSUPPORTED in this case.
             */
            if (NumberUtils.length(quickCheckHash) <= 0) {
                // TODO consider limiting it - e.g., if the requested effective length is <= than some (configurable)
                // threshold
                hashMatches = true;
            } else {
                int readLen = channel.read(wb);
                if (readLen < 0) {
                    throw new EOFException("EOF while read initial buffer from " + path);
                }
                effectiveLength -= readLen;
                digest.update(digestBuf, 0, readLen);

                hashValue = digest.digest();
                hashMatches = Arrays.equals(quickCheckHash, hashValue);
                if (hashMatches) {
                    /*
                     * Need to re-initialize the digester due to the Javadoc:
                     *
                     * "The digest method can be called once for a given number of updates. After digest has been
                     * called, the MessageDigest object is reset to its initialized state."
                     */
                    if (effectiveLength > 0L) {
                        digest = BuiltinDigests.md5.create();
                        digest.init();
                        digest.update(digestBuf, 0, readLen);
                        hashValue = null; // start again
                    }
                } else {
                    if (traceEnabled) {
                        log.trace("doMD5Hash({})({}) offset={}, length={} - quick-hash mismatched expected={}, actual={}",
                                session, path, startOffset, length,
                                BufferUtils.toHex(':', quickCheckHash),
                                BufferUtils.toHex(':', hashValue));
                    }
                }
            }

            if (hashMatches) {
                while (effectiveLength > 0L) {
                    int remainLen = Math.min(digestBuf.length, (int) effectiveLength);
                    ByteBuffer bb = wb;
                    if (remainLen < digestBuf.length) {
                        bb = ByteBuffer.wrap(digestBuf, 0, remainLen);
                    }
                    bb.clear(); // prepare for next read

                    int readLen = channel.read(bb);
                    if (readLen < 0) {
                        break; // user may have specified more than we have available
                    }
                    effectiveLength -= readLen;
                    digest.update(digestBuf, 0, readLen);
                }

                if (hashValue == null) { // check if did any more iterations after the quick hash
                    hashValue = digest.digest();
                }
            } else {
                hashValue = GenericUtils.EMPTY_BYTE_ARRAY;
            }

            accessor.closeFile(session, this, null, path, null, channel, Collections.emptySet());
        }

        if (traceEnabled) {
            log.trace("doMD5Hash({})({}) offset={}, length={} - matches={}, quick={} hash={}",
                    session, path, startOffset, length, hashMatches,
                    BufferUtils.toHex(':', quickCheckHash),
                    BufferUtils.toHex(':', hashValue));
        }

        return hashValue;
    }

    protected abstract void doCheckFileHash(
            int id, String targetType, String target, Collection<String> algos,
            long startOffset, long length, int blockSize, Buffer buffer)
            throws Exception;

    protected void doReadLink(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        String l;
        try {
            if (log.isDebugEnabled()) {
                log.debug("doReadLink({})[id={}] SSH_FXP_READLINK path={}",
                        getServerSession(), id, path);
            }
            l = doReadLink(id, path);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_READLINK, path);
            return;
        }

        sendLink(prepareReply(buffer), id, l);
    }

    protected String doReadLink(int id, String path) throws IOException {
        Path link = resolveFile(path);
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        String target = accessor.resolveLinkTarget(getServerSession(), this, link);
        if (log.isDebugEnabled()) {
            log.debug("doReadLink({})[id={}] path={}[{}]: {}",
                    getServerSession(), id, path, link, target);
        }
        return target;
    }

    protected void doRename(Buffer buffer, int id) throws IOException {
        String oldPath = buffer.getString();
        String newPath = buffer.getString();
        int flags = 0;
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V5) {
            flags = buffer.getInt();
        }
        try {
            doRename(id, oldPath, newPath, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_RENAME, oldPath, newPath, flags);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doRename(int id, String oldPath, String newPath, int flags) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doRename({})[id={}] SSH_FXP_RENAME (oldPath={}, newPath={}, flags=0x{})",
                    getServerSession(), id, oldPath, newPath, Integer.toHexString(flags));
        }

        Collection<CopyOption> opts = Collections.emptyList();
        if (flags != 0) {
            opts = new ArrayList<>();
            if ((flags & SftpConstants.SSH_FXP_RENAME_ATOMIC) == SftpConstants.SSH_FXP_RENAME_ATOMIC) {
                opts.add(StandardCopyOption.ATOMIC_MOVE);
            }
            if ((flags & SftpConstants.SSH_FXP_RENAME_OVERWRITE) == SftpConstants.SSH_FXP_RENAME_OVERWRITE) {
                opts.add(StandardCopyOption.REPLACE_EXISTING);
            }
        }

        doRename(id, oldPath, newPath, opts);
    }

    protected void doRename(int id, String oldPath, String newPath, Collection<CopyOption> opts) throws IOException {
        Path o = resolveFile(oldPath);
        Path n = resolveFile(newPath);
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();

        listener.moving(session, o, n, opts);
        try {
            SftpFileSystemAccessor accessor = getFileSystemAccessor();
            accessor.renameFile(session, this, o, n, opts);
        } catch (IOException | RuntimeException | Error e) {
            listener.moved(session, o, n, opts, e);
            throw e;
        }
        listener.moved(session, o, n, opts, null);
    }

    // see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-extensions-00#section-7
    protected void doCopyData(Buffer buffer, int id) throws IOException {
        String readHandle = buffer.getString();
        long readOffset = buffer.getLong();
        long readLength = buffer.getLong();
        String writeHandle = buffer.getString();
        long writeOffset = buffer.getLong();
        try {
            doCopyData(id, readHandle, readOffset, readLength, writeHandle, writeOffset);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, SftpConstants.EXT_COPY_DATA,
                    readHandle, readOffset, readLength, writeHandle, writeOffset);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doCopyData(
            int id, String readHandle, long readOffset, long readLength, String writeHandle, long writeOffset)
            throws IOException;

    // see https://tools.ietf.org/html/draft-ietf-secsh-filexfer-extensions-00#section-6
    protected void doCopyFile(Buffer buffer, int id) throws IOException {
        String srcFile = buffer.getString();
        String dstFile = buffer.getString();
        boolean overwriteDestination = buffer.getBoolean();

        try {
            doCopyFile(id, srcFile, dstFile, overwriteDestination);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_EXTENDED, SftpConstants.EXT_COPY_FILE, srcFile, dstFile, overwriteDestination);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doCopyFile(
            int id, String srcFile, String dstFile, boolean overwriteDestination)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doCopyFile({})[id={}] SSH_FXP_EXTENDED[{}] (src={}, dst={}, overwrite=0x{})",
                    getServerSession(), id, SftpConstants.EXT_COPY_FILE,
                    srcFile, dstFile, overwriteDestination);
        }

        doCopyFile(id, srcFile, dstFile,
                overwriteDestination
                        ? Collections.singletonList(StandardCopyOption.REPLACE_EXISTING)
                        : Collections.emptyList());
    }

    protected void doCopyFile(
            int id, String srcFile, String dstFile, Collection<CopyOption> opts)
            throws IOException {
        Path src = resolveFile(srcFile);
        Path dst = resolveFile(dstFile);
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        accessor.copyFile(getServerSession(), this, src, dst, opts);
    }

    protected void doBlock(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        long length = buffer.getLong();
        int mask = buffer.getInt();

        try {
            doBlock(id, handle, offset, length, mask);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_BLOCK, handle, offset, length, mask);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doBlock(
            int id, String handle, long offset, long length, int mask)
            throws IOException;

    protected void doUnblock(Buffer buffer, int id) throws IOException {
        String handle = buffer.getString();
        long offset = buffer.getLong();
        long length = buffer.getLong();
        try {
            doUnblock(id, handle, offset, length);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_UNBLOCK, handle, offset, length);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected abstract void doUnblock(
            int id, String handle, long offset, long length)
            throws IOException;

    protected void doStat(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        int flags = SftpConstants.SSH_FILEXFER_ATTR_ALL;
        int version = getVersion();
        if (version >= SftpConstants.SFTP_V4) {
            flags = buffer.getInt();
        }

        Map<String, Object> attrs;
        try {
            attrs = doStat(id, path, flags);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_STAT, path, flags);
            return;
        }

        sendAttrs(prepareReply(buffer), id, attrs);
    }

    protected Map<String, Object> doStat(int id, String path, int flags) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doStat({})[id={}] SSH_FXP_STAT (path={}, flags=0x{})",
                    getServerSession(), id, path, Integer.toHexString(flags));
        }

        /*
         * SSH_FXP_STAT and SSH_FXP_LSTAT only differ in that SSH_FXP_STAT follows symbolic links on the server, whereas
         * SSH_FXP_LSTAT does not.
         */
        Path p = resolveFile(path);
        return resolveFileAttributes(p, flags, IoUtils.getLinkOptions(true));
    }

    protected void doRealPath(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        boolean debugEnabled = log.isDebugEnabled();
        ServerSession session = getServerSession();
        if (debugEnabled) {
            log.debug("doRealPath({})[id={}] SSH_FXP_REALPATH (path={})", session, id, path);
        }
        path = GenericUtils.trimToEmpty(path);
        if (GenericUtils.isEmpty(path)) {
            path = ".";
        }

        Map<String, ?> attrs = Collections.emptyMap();
        Map.Entry<Path, Boolean> result;
        try {
            int version = getVersion();
            if (version < SftpConstants.SFTP_V6) {
                /*
                 * See http://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt:
                 *
                 * The SSH_FXP_REALPATH request can be used to have the server canonicalize any given path name to an
                 * absolute path.
                 *
                 * See also SSHD-294
                 */
                Path p = resolveFile(path);
                LinkOption[] options = getPathResolutionLinkOption(SftpConstants.SSH_FXP_REALPATH, "", p);
                result = doRealPathV345(id, path, p, options);
            } else {
                /*
                 * See https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-8.9
                 *
                 * This field is optional, and if it is not present in the packet, it is assumed to be
                 * SSH_FXP_REALPATH_NO_CHECK.
                 */
                int control = SftpConstants.SSH_FXP_REALPATH_NO_CHECK;
                if (buffer.available() > 0) {
                    control = buffer.getUByte();
                    if (debugEnabled) {
                        log.debug("doRealPath({}) - control=0x{} for path={}",
                                session, Integer.toHexString(control), path);
                    }
                }

                Collection<String> extraPaths = new LinkedList<>();
                while (buffer.available() > 0) {
                    extraPaths.add(buffer.getString());
                }

                Path p = resolveFile(path);
                LinkOption[] options = getPathResolutionLinkOption(SftpConstants.SSH_FXP_REALPATH, "", p);
                result = doRealPathV6(id, path, extraPaths, p, options);

                p = result.getKey();
                options = getPathResolutionLinkOption(SftpConstants.SSH_FXP_REALPATH, "", p);
                Boolean status = result.getValue();
                switch (control) {
                    case SftpConstants.SSH_FXP_REALPATH_STAT_IF:
                        if (status == null) {
                            attrs = handleUnknownStatusFileAttributes(
                                    p, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
                        } else if (status) {
                            try {
                                attrs = getAttributes(p, options);
                            } catch (IOException e) {
                                debug("doRealPath({}) - failed ({}) to retrieve attributes of {}: {}",
                                        session, e.getClass().getSimpleName(), p, e.getMessage(), e);
                            }
                        } else {
                            if (debugEnabled) {
                                log.debug("doRealPath({}) - dummy attributes for non-existing file: {}", session, p);
                            }
                        }
                        break;
                    case SftpConstants.SSH_FXP_REALPATH_STAT_ALWAYS:
                        if (status == null) {
                            attrs = handleUnknownStatusFileAttributes(
                                    p, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
                        } else if (status) {
                            attrs = getAttributes(p, options);
                        } else {
                            throw new NoSuchFileException(
                                    p.toString(), p.toString(), "Real path N/A for target");
                        }
                        break;
                    case SftpConstants.SSH_FXP_REALPATH_NO_CHECK:
                        break;
                    default:
                        log.warn("doRealPath({}) unknown control value 0x{} for path={}",
                                session, Integer.toHexString(control), p);
                }
            }
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_REALPATH, path);
            return;
        }

        sendPath(prepareReply(buffer), id, result.getKey(), attrs);
    }

    protected SimpleImmutableEntry<Path, Boolean> doRealPathV6(
            int id, String path, Collection<String> extraPaths, Path p, LinkOption... options)
            throws IOException {
        int numExtra = GenericUtils.size(extraPaths);
        if (numExtra > 0) {
            if (log.isDebugEnabled()) {
                log.debug("doRealPathV6({})[id={}] path={}, extra={}",
                        getServerSession(), id, path, extraPaths);
            }
            StringBuilder sb = new StringBuilder(GenericUtils.length(path) + numExtra * 8);
            sb.append(path);

            for (String p2 : extraPaths) {
                p = p.resolve(p2);
                options = getPathResolutionLinkOption(
                        SftpConstants.SSH_FXP_REALPATH, "", p);
                sb.append('/').append(p2);
            }

            path = sb.toString();
        }

        return validateRealPath(id, path, p, options);
    }

    protected SimpleImmutableEntry<Path, Boolean> doRealPathV345(
            int id, String path, Path p, LinkOption... options)
            throws IOException {
        return validateRealPath(id, path, p, options);
    }

    /**
     * @param  id          The request identifier
     * @param  path        The original path
     * @param  f           The resolve {@link Path}
     * @param  options     The {@link LinkOption}s to use to verify file existence and access
     * @return             A {@link SimpleImmutableEntry} whose key is the <U>absolute <B>normalized</B></U>
     *                     {@link Path} and value is a {@link Boolean} indicating its status
     * @throws IOException If failed to validate the file
     * @see                IoUtils#checkFileExists(Path, LinkOption...)
     */
    protected SimpleImmutableEntry<Path, Boolean> validateRealPath(
            int id, String path, Path f, LinkOption... options)
            throws IOException {
        Path p = normalize(f);
        Boolean status = IoUtils.checkFileExists(p, options);
        return new SimpleImmutableEntry<>(p, status);
    }

    protected void doRemoveDirectory(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        try {
            doRemoveDirectory(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_RMDIR, path);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doRemoveDirectory(
            int id, String path, LinkOption... options)
            throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doRemoveDirectory({})[id={}] SSH_FXP_RMDIR (path={})[{}]",
                    getServerSession(), id, path, p);
        }
        if (Files.isDirectory(p, options)) {
            doRemove(id, p, true);
        } else {
            throw signalRemovalPreConditionFailure(
                    id, path, p, new NotDirectoryException(p.toString()), true);
        }
    }

    /**
     * Called when need to delete a file / directory - also informs the {@link SftpEventListener}
     *
     * @param  id          Deletion request ID
     * @param  p           {@link Path} to delete
     * @param  isDirectory Whether the requested path represents a directory or a regular file
     * @throws IOException If failed to delete
     */
    protected void doRemove(int id, Path p, boolean isDirectory) throws IOException {
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();

        listener.removing(session, p, isDirectory);
        try {
            SftpFileSystemAccessor accessor = getFileSystemAccessor();
            accessor.removeFile(session, this, p, isDirectory);
        } catch (IOException | RuntimeException | Error e) {
            listener.removed(session, p, isDirectory, e);
            throw e;
        }
        listener.removed(session, p, isDirectory, null);
    }

    protected void doMakeDirectory(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        Map<String, ?> attrs = readAttrs(buffer);
        try {
            doMakeDirectory(id, path, attrs, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e,
                    SftpConstants.SSH_FXP_MKDIR, path, attrs);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doMakeDirectory(
            int id, String path, Map<String, ?> attrs, LinkOption... options)
            throws IOException {
        Path p = resolveFile(path);
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("doMakeDirectory({})[id={}] SSH_FXP_MKDIR (path={}[{}], attrs={})",
                    session, id, path, p, attrs);
        }

        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw new AccessDeniedException(
                    p.toString(), p.toString(), "Cannot validate make-directory existence");
        }

        if (status) {
            if (Files.isDirectory(p, options)) {
                throw new FileAlreadyExistsException(
                        p.toString(), p.toString(), "Target directory already exists");
            } else {
                throw new FileAlreadyExistsException(
                        p.toString(), p.toString(), "Already exists as a file");
            }
        } else {
            SftpEventListener listener = getSftpEventListenerProxy();
            listener.creating(session, p, attrs);
            try {
                SftpFileSystemAccessor accessor = getFileSystemAccessor();
                accessor.createDirectory(session, this, p);
                boolean followLinks = resolvePathResolutionFollowLinks(
                        SftpConstants.SSH_FXP_MKDIR, "", p);
                doSetAttributes(p, attrs, followLinks);
            } catch (IOException | RuntimeException | Error e) {
                listener.created(session, p, attrs, e);
                throw e;
            }
            listener.created(session, p, attrs, null);
        }
    }

    protected void doRemove(Buffer buffer, int id) throws IOException {
        String path = buffer.getString();
        try {
            /*
             * If 'filename' is a symbolic link, the link is removed, not the file it points to.
             */
            doRemove(id, path, IoUtils.getLinkOptions(false));
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_REMOVE, path);
            return;
        }

        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OK, "");
    }

    protected void doRemove(int id, String path, LinkOption... options) throws IOException {
        Path p = resolveFile(path);
        if (log.isDebugEnabled()) {
            log.debug("doRemove({})[id={}] SSH_FXP_REMOVE (path={}[{}])",
                    getServerSession(), id, path, p);
        }

        Boolean status = IoUtils.checkFileExists(p, options);
        if (status == null) {
            throw signalRemovalPreConditionFailure(id, path, p,
                    new AccessDeniedException(
                            p.toString(), p.toString(), "Cannot determine existence of remove candidate"),
                    false);
        } else if (!status) {
            throw signalRemovalPreConditionFailure(id, path, p,
                    new NoSuchFileException(
                            p.toString(), p.toString(), "Removal candidate not found"),
                    false);
        } else if (Files.isDirectory(p, options)) {
            throw signalRemovalPreConditionFailure(id, path, p,
                    new SftpException(
                            SftpConstants.SSH_FX_FILE_IS_A_DIRECTORY, p.toString() + " is a folder"),
                    false);
        } else {
            doRemove(id, p, false);
        }
    }

    protected <E extends IOException> E signalRemovalPreConditionFailure(
            int id, String pathValue, Path path, E thrown, boolean isRemoveDirectory)
            throws IOException {
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("signalRemovalPreConditionFailure(id={})[{}] signal {} for (directory={}) {}: {}",
                    id, pathValue, thrown.getClass().getSimpleName(), isRemoveDirectory, path, thrown.getMessage());
        }

        listener.removing(session, path, isRemoveDirectory);
        listener.removed(session, path, isRemoveDirectory, thrown);
        return thrown;
    }

    protected void doExtended(Buffer buffer, int id) throws IOException {
        String extension = buffer.getString();
        try {
            SftpEventListener listener = getSftpEventListenerProxy();
            ServerSession session = getServerSession();
            listener.receivedExtension(session, extension, id);
        } catch (IOException | RuntimeException e) {
            sendStatus(prepareReply(buffer), id, e, SftpConstants.SSH_FXP_EXTENDED, extension);
            return;
        }
        executeExtendedCommand(buffer, id, extension);
    }

    /**
     * @param  buffer      The command {@link Buffer}
     * @param  id          The request id
     * @param  extension   The extension name
     * @throws IOException If failed to execute the extension
     */
    protected void executeExtendedCommand(Buffer buffer, int id, String extension) throws IOException {
        switch (extension) {
            case SftpConstants.EXT_TEXT_SEEK:
                doTextSeek(buffer, id);
                break;
            case SftpConstants.EXT_VERSION_SELECT:
                doVersionSelect(buffer, id);
                break;
            case SftpConstants.EXT_COPY_FILE:
                doCopyFile(buffer, id);
                break;
            case SftpConstants.EXT_COPY_DATA:
                doCopyData(buffer, id);
                break;
            case SftpConstants.EXT_MD5_HASH:
            case SftpConstants.EXT_MD5_HASH_HANDLE:
                doMD5Hash(buffer, id, extension);
                break;
            case SftpConstants.EXT_CHECK_FILE_HANDLE:
            case SftpConstants.EXT_CHECK_FILE_NAME:
                doCheckFileHash(buffer, id, extension);
                break;
            case FsyncExtensionParser.NAME:
                doOpenSSHFsync(buffer, id);
                break;
            case SftpConstants.EXT_SPACE_AVAILABLE:
                doSpaceAvailable(buffer, id);
                break;
            case HardLinkExtensionParser.NAME:
                doOpenSSHHardLink(buffer, id);
                break;
            case LSetStatExtensionParser.NAME:
                doSetStat(buffer, id, extension, -1, Boolean.FALSE);
                break;
            default:
                doUnsupportedExtension(buffer, id, extension);
        }
    }

    protected void doUnsupportedExtension(
            Buffer buffer, int id, String extension)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("executeExtendedCommand({}) received unsupported SSH_FXP_EXTENDED({})",
                    getServerSession(), extension);
        }
        sendStatus(prepareReply(buffer), id, SftpConstants.SSH_FX_OP_UNSUPPORTED,
                "Command SSH_FXP_EXTENDED(" + extension + ") is unsupported or not implemented");
    }

    protected void appendExtensions(Buffer buffer, String supportedVersions) {
        ServerSession session = getServerSession();
        appendVersionsExtension(buffer, supportedVersions, session);
        appendNewlineExtension(buffer, session);
        appendVendorIdExtension(buffer, VersionProperties.getVersionProperties(), session);
        appendOpenSSHExtensions(buffer, session);
        appendAclSupportedExtension(buffer, session);

        Map<String, OptionalFeature> extensions = getSupportedClientExtensions(session);
        int numExtensions = GenericUtils.size(extensions);
        List<String> extras = (numExtensions <= 0) ? Collections.emptyList() : new ArrayList<>(numExtensions);
        if (numExtensions > 0) {
            boolean debugEnabled = log.isDebugEnabled();
            for (Map.Entry<String, OptionalFeature> ee : extensions.entrySet()) {
                String name = ee.getKey();
                OptionalFeature f = ee.getValue();
                if (!f.isSupported()) {
                    if (debugEnabled) {
                        log.debug("appendExtensions({}) skip unsupported extension={}", session, name);
                    }
                    continue;
                }

                extras.add(name);
            }
        }

        appendSupportedExtension(buffer, extras);
        appendSupported2Extension(buffer, extras);
    }

    protected int appendAclSupportedExtension(Buffer buffer, ServerSession session) {
        Collection<Integer> maskValues = resolveAclSupportedCapabilities(session);
        int mask = AclSupportedParser.AclCapabilities.constructAclCapabilities(maskValues);
        if (mask != 0) {
            if (log.isTraceEnabled()) {
                log.trace("appendAclSupportedExtension({}) capabilities={}",
                        session, AclSupportedParser.AclCapabilities.decodeAclCapabilities(mask));
            }

            buffer.putString(SftpConstants.EXT_ACL_SUPPORTED);

            // placeholder for length
            int lenPos = buffer.wpos();
            buffer.putInt(0);
            buffer.putInt(mask);
            BufferUtils.updateLengthPlaceholder(buffer, lenPos);
        }

        return mask;
    }

    protected Collection<Integer> resolveAclSupportedCapabilities(ServerSession session) {
        String override = SftpModuleProperties.ACL_SUPPORTED_MASK.getOrNull(session);
        if (override == null) {
            return DEFAULT_ACL_SUPPORTED_MASK;
        }

        // empty means not supported
        if (log.isDebugEnabled()) {
            log.debug("resolveAclSupportedCapabilities({}) override='{}'", session, override);
        }

        if (override.length() == 0) {
            return Collections.emptySet();
        }

        String[] names = GenericUtils.split(override, ',');
        Set<Integer> maskValues = new HashSet<>(names.length);
        for (String n : names) {
            Integer v = ValidateUtils.checkNotNull(
                    AclSupportedParser.AclCapabilities.getAclCapabilityValue(n), "Unknown ACL capability: %s", n);
            maskValues.add(v);
        }

        return maskValues;
    }

    protected List<OpenSSHExtension> appendOpenSSHExtensions(Buffer buffer, ServerSession session) {
        List<OpenSSHExtension> extList = resolveOpenSSHExtensions(session);
        if (GenericUtils.isEmpty(extList)) {
            return extList;
        }

        for (OpenSSHExtension ext : extList) {
            buffer.putString(ext.getName());
            buffer.putString(ext.getVersion());
        }

        return extList;
    }

    protected List<OpenSSHExtension> resolveOpenSSHExtensions(ServerSession session) {
        String value = SftpModuleProperties.OPENSSH_EXTENSIONS.getOrNull(session);
        if (value == null) { // No override
            return DEFAULT_OPEN_SSH_EXTENSIONS;
        }

        if (log.isDebugEnabled()) {
            log.debug("resolveOpenSSHExtensions({}) override='{}'", session, value);
        }

        String[] pairs = GenericUtils.split(value, ',');
        int numExts = GenericUtils.length(pairs);
        if (numExts <= 0) { // User does not want to report ANY extensions
            return Collections.emptyList();
        }

        List<OpenSSHExtension> extList = new ArrayList<>(numExts);
        for (String nvp : pairs) {
            nvp = GenericUtils.trimToEmpty(nvp);
            if (GenericUtils.isEmpty(nvp)) {
                continue;
            }

            int pos = nvp.indexOf('=');
            ValidateUtils.checkTrue(
                    (pos > 0) && (pos < (nvp.length() - 1)), "Malformed OpenSSH extension spec: %s", nvp);

            String name = GenericUtils.trimToEmpty(nvp.substring(0, pos));
            String version = GenericUtils.trimToEmpty(nvp.substring(pos + 1));
            extList.add(new OpenSSHExtension(
                    name,
                    ValidateUtils.checkNotNullAndNotEmpty(
                            version, "No version specified for OpenSSH extension %s", name)));
        }

        return extList;
    }

    protected Map<String, OptionalFeature> getSupportedClientExtensions(ServerSession session) {
        String value = SftpModuleProperties.CLIENT_EXTENSIONS.getOrNull(session);
        if (value == null) {
            return DEFAULT_SUPPORTED_CLIENT_EXTENSIONS;
        }

        if (log.isDebugEnabled()) {
            log.debug("getSupportedClientExtensions({}) override='{}'", session, value);
        }

        if (value.length() <= 0) { // means don't report any extensions
            return Collections.emptyMap();
        }

        if (value.indexOf(',') <= 0) {
            return Collections.singletonMap(value, OptionalFeature.TRUE);
        }

        String[] comps = GenericUtils.split(value, ',');
        Map<String, OptionalFeature> result = new LinkedHashMap<>(comps.length);
        for (String c : comps) {
            result.put(c, OptionalFeature.TRUE);
        }

        return result;
    }

    /**
     * Appends the &quot;versions&quot; extension to the buffer. <B>Note:</B> if overriding this method make sure you
     * either do not append anything or use the correct extension name
     *
     * @param buffer  The {@link Buffer} to append to
     * @param value   The recommended value - ignored if {@code null}/empty
     * @param session The {@link ServerSession} for which this extension is added
     * @see           SftpConstants#EXT_VERSIONS
     */
    protected void appendVersionsExtension(
            Buffer buffer, String value, ServerSession session) {
        if (GenericUtils.isEmpty(value)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("appendVersionsExtension({}) value={}", session, value);
        }

        buffer.putString(SftpConstants.EXT_VERSIONS);
        buffer.putString(value);
    }

    /**
     * Appends the &quot;newline&quot; extension to the buffer. <B>Note:</B> if overriding this method make sure you
     * either do not append anything or use the correct extension name
     *
     * @param buffer  The {@link Buffer} to append to
     * @param session The {@link ServerSession} for which this extension is added
     * @see           SftpConstants#EXT_NEWLINE
     * @see           #resolveNewlineValue(ServerSession)
     */
    protected void appendNewlineExtension(Buffer buffer, ServerSession session) {
        String value = resolveNewlineValue(session);
        if (GenericUtils.isEmpty(value)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("appendNewlineExtension({}) value={}",
                    getServerSession(), BufferUtils.toHex(':', value.getBytes(StandardCharsets.UTF_8)));
        }

        buffer.putString(SftpConstants.EXT_NEWLINE);
        buffer.putString(value);
    }

    protected String resolveNewlineValue(ServerSession session) {
        return SftpModuleProperties.NEWLINE_VALUE.getRequired(session);
    }

    /**
     * Appends the &quot;vendor-id&quot; extension to the buffer. <B>Note:</B> if overriding this method make sure you
     * either do not append anything or use the correct extension name
     *
     * @param buffer            The {@link Buffer} to append to
     * @param versionProperties The currently available version properties - ignored if {@code null}/empty. The code
     *                          expects the following values:
     *                          <UL>
     *                          <LI>{@code groupId} - as the vendor name</LI>
     *                          <LI>{@code artifactId} - as the product name</LI>
     *                          <LI>{@code version} - as the product version</LI>
     *                          </UL>
     * @param session           The {@link ServerSession} for which these properties are added
     * @see                     SftpConstants#EXT_VENDOR_ID
     * @see                     <A HREF=
     *                          "http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt">DRAFT
     *                          09 - section 4.4</A>
     */
    protected void appendVendorIdExtension(
            Buffer buffer, Map<String, ?> versionProperties, ServerSession session) {
        if (GenericUtils.isEmpty(versionProperties)) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("appendVendorIdExtension({}): {}", session, versionProperties);
        }
        buffer.putString(SftpConstants.EXT_VENDOR_ID);

        PropertyResolver resolver = PropertyResolverUtils.toPropertyResolver(
                Collections.unmodifiableMap(versionProperties));
        // placeholder for length
        int lenPos = buffer.wpos();
        buffer.putInt(0);
        buffer.putString(resolver.getStringProperty("groupId", getClass().getPackage().getName())); // vendor-name
        buffer.putString(resolver.getStringProperty("artifactId", getClass().getSimpleName())); // product-name
        buffer.putString(resolver.getStringProperty("version", FactoryManager.DEFAULT_VERSION)); // product-version
        buffer.putLong(0L); // product-build-number
        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    /**
     * Appends the &quot;supported&quot; extension to the buffer. <B>Note:</B> if overriding this method make sure you
     * either do not append anything or use the correct extension name
     *
     * @param buffer The {@link Buffer} to append to
     * @param extras The extra extensions that are available and can be reported - may be {@code null}/empty
     */
    protected void appendSupportedExtension(Buffer buffer, Collection<String> extras) {
        buffer.putString(SftpConstants.EXT_SUPPORTED);

        int lenPos = buffer.wpos();
        buffer.putInt(0); // length placeholder
        // supported-attribute-mask
        buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_SIZE | SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS
                      | SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME | SftpConstants.SSH_FILEXFER_ATTR_CREATETIME
                      | SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME | SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP
                      | SftpConstants.SSH_FILEXFER_ATTR_BITS);
        // TODO: supported-attribute-bits
        buffer.putInt(0);
        // supported-open-flags
        buffer.putInt(SftpConstants.SSH_FXF_READ | SftpConstants.SSH_FXF_WRITE | SftpConstants.SSH_FXF_APPEND
                      | SftpConstants.SSH_FXF_CREAT | SftpConstants.SSH_FXF_TRUNC | SftpConstants.SSH_FXF_EXCL);
        // TODO: supported-access-mask
        buffer.putInt(0);
        // max-read-size
        buffer.putInt(0);
        // supported extensions
        buffer.putStringList(extras, false);

        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    /**
     * Appends the &quot;supported2&quot; extension to the buffer. <B>Note:</B> if overriding this method make sure you
     * either do not append anything or use the correct extension name
     *
     * @param buffer The {@link Buffer} to append to
     * @param extras The extra extensions that are available and can be reported - may be {@code null}/empty
     * @see          SftpConstants#EXT_SUPPORTED
     * @see          <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-10">DRAFT 13 section 5.4</A>
     */
    @SuppressWarnings("checkstyle:VariableDeclarationUsageDistance")
    protected void appendSupported2Extension(Buffer buffer, Collection<String> extras) {
        buffer.putString(SftpConstants.EXT_SUPPORTED2);

        int lenPos = buffer.wpos();
        buffer.putInt(0); // length placeholder
        // supported-attribute-mask
        buffer.putInt(SftpConstants.SSH_FILEXFER_ATTR_SIZE | SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS
                      | SftpConstants.SSH_FILEXFER_ATTR_ACCESSTIME | SftpConstants.SSH_FILEXFER_ATTR_CREATETIME
                      | SftpConstants.SSH_FILEXFER_ATTR_MODIFYTIME | SftpConstants.SSH_FILEXFER_ATTR_OWNERGROUP
                      | SftpConstants.SSH_FILEXFER_ATTR_BITS);
        // TODO: supported-attribute-bits
        buffer.putInt(0);
        // supported-open-flags
        buffer.putInt(SftpConstants.SSH_FXF_ACCESS_DISPOSITION | SftpConstants.SSH_FXF_APPEND_DATA);
        // TODO: supported-access-mask
        buffer.putInt(0);
        // max-read-size
        buffer.putInt(0);
        // supported-open-block-vector
        buffer.putShort(0);
        // supported-block-vector
        buffer.putShort(0);
        // attrib-extension-count + attributes name
        buffer.putStringList(Collections.<String> emptyList(), true);
        // extension-count + supported extensions
        buffer.putStringList(extras, true);

        BufferUtils.updateLengthPlaceholder(buffer, lenPos);
    }

    protected void sendHandle(Buffer buffer, int id, String handle) throws IOException {
        buffer.putByte((byte) SftpConstants.SSH_FXP_HANDLE);
        buffer.putInt(id);
        buffer.putString(handle);
        send(buffer);
    }

    protected void sendAttrs(Buffer buffer, int id, Map<String, ?> attributes) throws IOException {
        buffer.putByte((byte) SftpConstants.SSH_FXP_ATTRS);
        buffer.putInt(id);
        writeAttrs(buffer, attributes);
        send(buffer);
    }

    protected void sendLink(Buffer buffer, int id, String link) throws IOException {
        // in case we are running on Windows
        String unixPath = link.replace(File.separatorChar, '/');

        buffer.putByte((byte) SftpConstants.SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1); // one response
        buffer.putString(unixPath);

        /*
         * As per the spec (https://tools.ietf.org/html/draft-ietf-secsh-filexfer-02#section-6.10):
         *
         * The server will respond with a SSH_FXP_NAME packet containing only one name and a dummy attributes value.
         */
        Map<String, Object> attrs = Collections.emptyMap();
        int version = getVersion();
        if (version == SftpConstants.SFTP_V3) {
            buffer.putString(SftpHelper.getLongName(unixPath, attrs));
        }

        writeAttrs(buffer, attrs);
        SftpHelper.indicateEndOfNamesList(buffer, getVersion(), getServerSession());
        send(buffer);
    }

    protected void sendPath(
            Buffer buffer, int id, Path f, Map<String, ?> attrs)
            throws IOException {
        buffer.putByte((byte) SftpConstants.SSH_FXP_NAME);
        buffer.putInt(id);
        buffer.putInt(1); // one reply

        String originalPath = f.toString();
        // in case we are running on Windows
        String unixPath = originalPath.replace(File.separatorChar, '/');
        buffer.putString(unixPath);

        int version = getVersion();
        if (version == SftpConstants.SFTP_V3) {
            buffer.putString(getLongName(f, getShortName(f), attrs));
        }

        writeAttrs(buffer, attrs);
        SftpHelper.indicateEndOfNamesList(buffer, getVersion(), getServerSession());
        send(buffer);
    }

    /**
     * @param  id          Request id
     * @param  handle      The (opaque) handle assigned to this directory
     * @param  dir         The {@link DirectoryHandle}
     * @param  buffer      The {@link Buffer} to write the results
     * @param  maxSize     Max. buffer size
     * @param  options     The {@link LinkOption}-s to use when querying the directory contents
     * @return             Number of written entries
     * @throws IOException If failed to generate an entry
     */
    protected int doReadDir(
            int id, String handle, DirectoryHandle dir, Buffer buffer, int maxSize, LinkOption... options)
            throws IOException {
        int nb = 0;
        Map<String, Path> entries = new TreeMap<>(Comparator.naturalOrder());
        while ((dir.isSendDot() || dir.isSendDotDot() || dir.hasNext()) && (buffer.wpos() < maxSize)) {
            if (dir.isSendDot()) {
                writeDirEntry(id, dir, entries, buffer, nb, dir.getFile(), ".", options);
                dir.markDotSent(); // do not send it again
            } else if (dir.isSendDotDot()) {
                Path dirPath = dir.getFile();
                writeDirEntry(id, dir, entries, buffer, nb, dirPath.getParent(), "..", options);
                dir.markDotDotSent(); // do not send it again
            } else {
                Path f = dir.next();
                writeDirEntry(id, dir, entries, buffer, nb, f, getShortName(f), options);
            }

            nb++;
        }

        SftpEventListener listener = getSftpEventListenerProxy();
        listener.readEntries(getServerSession(), handle, dir, entries);
        return nb;
    }

    /**
     * @param  id          Request id
     * @param  dir         The {@link DirectoryHandle}
     * @param  entries     An in / out {@link Map} for updating the written entry - key = short name, value = entry
     *                     {@link Path}
     * @param  buffer      The {@link Buffer} to write the results
     * @param  index       Zero-based index of the entry to be written
     * @param  f           The entry {@link Path}
     * @param  shortName   The entry short name
     * @param  options     The {@link LinkOption}s to use for querying the entry-s attributes
     * @throws IOException If failed to generate the entry data
     */
    protected void writeDirEntry(
            int id, DirectoryHandle dir, Map<String, Path> entries, Buffer buffer,
            int index, Path f, String shortName, LinkOption... options)
            throws IOException {
        Map<String, ?> attrs = resolveFileAttributes(
                f, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
        entries.put(shortName, f);

        buffer.putString(shortName);
        int version = getVersion();
        if (version == SftpConstants.SFTP_V3) {
            String longName = getLongName(f, shortName, options);
            buffer.putString(longName);
            if (log.isTraceEnabled()) {
                log.trace("writeDirEntry(" + getServerSession() + ") id=" + id + ")[" + index + "] - "
                          + shortName + " [" + longName + "]: " + attrs);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("writeDirEntry(" + getServerSession() + "(id=" + id + ")[" + index + "] - "
                          + shortName + ": " + attrs);
            }
        }

        writeAttrs(buffer, attrs);
    }

    protected String getLongName(
            Path f, String shortName, LinkOption... options)
            throws IOException {
        return getLongName(f, shortName, true, options);
    }

    protected String getLongName(
            Path f, String shortName, boolean sendAttrs, LinkOption... options)
            throws IOException {
        Map<String, Object> attributes;
        if (sendAttrs) {
            attributes = getAttributes(f, options);
        } else {
            attributes = Collections.emptyMap();
        }
        return getLongName(f, shortName, attributes);
    }

    protected String getLongName(
            Path f, String shortName, Map<String, ?> attributes)
            throws IOException {
        return SftpHelper.getLongName(shortName, attributes);
    }

    protected String getShortName(Path f) throws IOException {
        Path nrm = normalize(f);
        int count = nrm.getNameCount();
        /*
         * According to the javadoc:
         *
         * The number of elements in the path, or 0 if this path only represents a root component
         */
        if (OsUtils.isUNIX()) {
            Path name = f.getFileName();
            if (name == null) {
                Path p = resolveFile(".");
                name = p.getFileName();
            }

            if (name == null) {
                if (count > 0) {
                    name = nrm.getFileName();
                }
            }

            if (name != null) {
                return name.toString();
            } else {
                return nrm.toString();
            }
        } else { // need special handling for Windows root drives
            if (count > 0) {
                Path name = nrm.getFileName();
                return name.toString();
            } else {
                return nrm.toString().replace(File.separatorChar, '/');
            }
        }
    }

    protected NavigableMap<String, Object> resolveFileAttributes(
            Path file, int flags, LinkOption... options)
            throws IOException {
        Boolean status = IoUtils.checkFileExists(file, options);
        if (status == null) {
            return handleUnknownStatusFileAttributes(file, flags, options);
        } else if (!status) {
            throw new NoSuchFileException(file.toString(), file.toString(), "Attributes N/A for target");
        } else {
            return getAttributes(file, flags, options);
        }
    }

    protected void writeAttrs(Buffer buffer, Map<String, ?> attributes) throws IOException {
        SftpHelper.writeAttrs(buffer, getVersion(), attributes);
    }

    protected NavigableMap<String, Object> getAttributes(Path file, LinkOption... options)
            throws IOException {
        return getAttributes(file, SftpConstants.SSH_FILEXFER_ATTR_ALL, options);
    }

    protected NavigableMap<String, Object> handleUnknownStatusFileAttributes(
            Path file, int flags, LinkOption... options)
            throws IOException {
        UnsupportedAttributePolicy unsupportedAttributePolicy = getUnsupportedAttributePolicy();
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case ThrowException:
                throw new AccessDeniedException(
                        file.toString(), file.toString(), "Cannot determine existence for attributes of target");
            case Warn:
                log.warn("handleUnknownStatusFileAttributes(" + getServerSession() + ")[" + file
                         + "] cannot determine existence");
                break;
            default:
                log.warn("handleUnknownStatusFileAttributes(" + getServerSession() + ")[" + file + "] unknown policy: "
                         + unsupportedAttributePolicy);
        }

        return getAttributes(file, flags, options);
    }

    /**
     * @param  file        The {@link Path} location for the required attributes
     * @param  flags       A mask of the original required attributes - ignored by the default implementation
     * @param  options     The {@link LinkOption}s to use in order to access the file if necessary
     * @return             A {@link Map} of the retrieved attributes
     * @throws IOException If failed to access the file
     * @see                #resolveMissingFileAttributes(Path, int, Map, LinkOption...)
     */
    protected NavigableMap<String, Object> getAttributes(Path file, int flags, LinkOption... options)
            throws IOException {
        FileSystem fs = file.getFileSystem();
        Collection<String> supportedViews = fs.supportedFileAttributeViews();
        NavigableMap<String, Object> attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Collection<String> views;

        if (GenericUtils.isEmpty(supportedViews)) {
            views = Collections.emptyList();
        } else if (supportedViews.contains("unix")) {
            views = SftpFileSystemAccessor.DEFAULT_UNIX_VIEW;
        } else {
            views = GenericUtils.map(supportedViews, v -> v + ":*");
        }

        for (String v : views) {
            Map<String, ?> ta = readFileAttributes(file, v, options);
            if (GenericUtils.isNotEmpty(ta)) {
                attrs.putAll(ta);
            }
        }

        Map<String, ?> completions = resolveMissingFileAttributes(file, flags, attrs, options);
        if (GenericUtils.isNotEmpty(completions)) {
            attrs.putAll(completions);
        }

        return attrs;
    }

    /**
     * Called by {@link #getAttributes(Path, int, LinkOption...)} in order to complete any attributes that could not be
     * retrieved via the supported file system views. These attributes are deemed important so an extra effort is made
     * to provide a value for them
     *
     * @param  file        The {@link Path} location for the required attributes
     * @param  flags       A mask of the original required attributes - ignored by the default implementation
     * @param  current     The {@link Map} of attributes already retrieved - may be {@code null}/empty and/or
     *                     unmodifiable
     * @param  options     The {@link LinkOption}s to use in order to access the file if necessary
     * @return             A {@link Map} of the extra attributes whose values need to be updated in the original map.
     *                     <B>Note:</B> it is allowed to specify values which <U>override</U> existing ones - the
     *                     default implementation does not override values that have a non-{@code null} value
     * @throws IOException If failed to access the attributes - in which case an <U>error</U> is returned to the SFTP
     *                     client
     * @see                SftpFileSystemAccessor#FILEATTRS_RESOLVERS
     */
    protected NavigableMap<String, Object> resolveMissingFileAttributes(
            Path file, int flags, Map<String, Object> current, LinkOption... options)
            throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        ServerSession session = getServerSession();
        NavigableMap<String, Object> attrs = null;
        // Cannot use forEach because the attrs variable is not effectively final
        for (Map.Entry<String, FileInfoExtractor<?>> re : SftpFileSystemAccessor.FILEATTRS_RESOLVERS.entrySet()) {
            String name = re.getKey();
            Object value = GenericUtils.isEmpty(current) ? null : current.get(name);
            FileInfoExtractor<?> x = re.getValue();
            try {
                Object resolved = resolveMissingFileAttributeValue(file, name, value, x, options);
                if (Objects.equals(resolved, value)) {
                    continue;
                }

                if (attrs == null) {
                    attrs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                }

                attrs.put(name, resolved);

                if (debugEnabled) {
                    log.debug("resolveMissingFileAttributes({})[{}[{}]] replace {} with {}",
                            session, file, name, value, resolved);
                }
            } catch (IOException e) {
                warn("resolveMissingFileAttributes({})[{}[{}]] failed ({}) to resolve missing value: {}",
                        session, file, name, e.getClass().getSimpleName(), e.getMessage(), e);
            }
        }

        if (attrs == null) {
            return Collections.emptyNavigableMap();
        } else {
            return attrs;
        }
    }

    protected Object resolveMissingFileAttributeValue(
            Path file, String name, Object value, FileInfoExtractor<?> x, LinkOption... options)
            throws IOException {
        if (value != null) {
            return value;
        } else {
            return x.infoOf(file, options);
        }
    }

    protected NavigableMap<String, Object> addMissingAttribute(
            Path file, NavigableMap<String, Object> current,
            String name, FileInfoExtractor<?> x, LinkOption... options)
            throws IOException {
        Object value = GenericUtils.isEmpty(current) ? null : current.get(name);
        if (value != null) { // already have the value
            return current;
        }

        // skip if still no value
        value = x.infoOf(file, options);
        if (value == null) {
            return current;
        }

        if (current == null) {
            current = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        }

        current.put(name, value);
        return current;
    }

    protected NavigableMap<String, Object> readFileAttributes(
            Path file, String view, LinkOption... options)
            throws IOException {
        try {
            SftpFileSystemAccessor accessor = getFileSystemAccessor();
            Map<String, ?> attrs = accessor.readFileAttributes(
                    getServerSession(), this, file, view, options);
            if (GenericUtils.isEmpty(attrs)) {
                return Collections.emptyNavigableMap();
            }

            NavigableMap<String, Object> sorted = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            sorted.putAll(attrs);
            return sorted;
        } catch (IOException e) {
            return handleReadFileAttributesException(file, view, options, e);
        }
    }

    protected NavigableMap<String, Object> handleReadFileAttributesException(
            Path file, String view, LinkOption[] options, IOException e)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("handleReadFileAttributesException(" + file + ")[" + view + "] details", e);
        }

        UnsupportedAttributePolicy unsupportedAttributePolicy = getUnsupportedAttributePolicy();
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("handleReadFileAttributesException(" + file + ")[" + view + "] " + e.getClass().getSimpleName() + ": "
                         + e.getMessage());
                break;
            case ThrowException:
                throw e;
            default:
                log.warn("handleReadFileAttributesException(" + file + ")[" + view + "]"
                         + " Unknown policy (" + unsupportedAttributePolicy + ")"
                         + " for " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        return Collections.emptyNavigableMap();
    }

    protected void doSetAttributes(
            Path file, Map<String, ?> attributes, boolean followLinks)
            throws IOException {
        SftpEventListener listener = getSftpEventListenerProxy();
        ServerSession session = getServerSession();
        listener.modifyingAttributes(session, file, attributes);
        try {
            setFileAttributes(file, attributes, IoUtils.getLinkOptions(followLinks));
        } catch (IOException | RuntimeException | Error e) {
            listener.modifiedAttributes(session, file, attributes, e);
            throw e;
        }
        listener.modifiedAttributes(session, file, attributes, null);
    }

    protected LinkOption[] getPathResolutionLinkOption(int cmd, String extension, Path path) throws IOException {
        boolean followLinks = resolvePathResolutionFollowLinks(cmd, extension, path);
        return IoUtils.getLinkOptions(followLinks);
    }

    protected boolean resolvePathResolutionFollowLinks(int cmd, String extension, Path path) throws IOException {
        ServerSession session = getServerSession();
        return SftpModuleProperties.AUTO_FOLLOW_LINKS.getRequired(session);
    }

    protected void setFileAttributes(
            Path file, Map<String, ?> attributes, LinkOption... options)
            throws IOException {
        Set<String> unsupported = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        // Cannot use forEach because of the potential IOException being thrown
        for (Map.Entry<String, ?> ae : attributes.entrySet()) {
            String attribute = ae.getKey();
            Object value = ae.getValue();
            String view = null;
            switch (attribute) {
                case "size": {
                    long newSize = ((Number) value).longValue();
                    SftpFileSystemAccessor accessor = getFileSystemAccessor();
                    ServerSession session = getServerSession();
                    Set<StandardOpenOption> openOptions = EnumSet.of(StandardOpenOption.WRITE);
                    try (SeekableByteChannel channel = accessor.openFile(session, this, null, file, null, openOptions)) {
                        channel.truncate(newSize);
                        accessor.closeFile(session, this, null, file, null, channel, openOptions);
                    }
                    continue;
                }
                case "uid":
                    view = "unix";
                    break;
                case "gid":
                    view = "unix";
                    break;
                case "owner":
                    view = "posix";
                    value = toUser(file, (UserPrincipal) value);
                    break;
                case "group":
                    view = "posix";
                    value = toGroup(file, (GroupPrincipal) value);
                    break;
                case "permissions":
                    view = "posix";
                    break;
                case "acl":
                    view = "acl";
                    break;
                case "creationTime":
                    view = "basic";
                    break;
                case "lastModifiedTime":
                    view = "basic";
                    break;
                case "lastAccessTime":
                    view = "basic";
                    break;
                case "extended":
                    view = "extended";
                    break;
                default: // ignored
            }
            if ((GenericUtils.length(view) > 0) && (value != null)) {
                try {
                    setFileAttribute(file, view, attribute, value, options);
                } catch (Exception e) {
                    handleSetFileAttributeFailure(file, view, attribute, value, unsupported, e);
                }
            }
        }

        handleUnsupportedAttributes(unsupported);
    }

    protected void handleSetFileAttributeFailure(
            Path file, String view, String attribute, Object value,
            Collection<String> unsupported, Exception e)
            throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        if (e instanceof UnsupportedOperationException) {
            if (debugEnabled) {
                log.debug("handleSetFileAttributeFailure({})[{}] {}:{}={} unsupported: {}",
                        getServerSession(), file, view, attribute, value, e.getMessage());
            }
            unsupported.add(attribute);
        } else {
            warn("handleSetFileAttributeFailure({})[{}] {}:{}={} - failed ({}) to set: {}",
                    getServerSession(), file, view, attribute, value, e.getClass().getSimpleName(), e.getMessage(), e);
            if (e instanceof IOException) {
                throw (IOException) e;
            } else {
                throw new IOException(e);
            }
        }
    }

    protected void setFileAttribute(
            Path file, String view, String attribute, Object value, LinkOption... options)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("setFileAttribute({})[{}] {}:{}={}",
                    getServerSession(), file, view, attribute, value);
        }

        if ("acl".equalsIgnoreCase(attribute) && "acl".equalsIgnoreCase(view)) {
            @SuppressWarnings("unchecked")
            List<AclEntry> acl = (List<AclEntry>) value;
            setFileAccessControl(file, acl, options);
        } else if ("permissions".equalsIgnoreCase(attribute)) {
            @SuppressWarnings("unchecked")
            Set<PosixFilePermission> perms = (Set<PosixFilePermission>) value;
            setFilePermissions(file, perms, options);
        } else if ("owner".equalsIgnoreCase(attribute) || "group".equalsIgnoreCase(attribute)) {
            setFileOwnership(file, attribute, (Principal) value, options);
        } else if ("creationTime".equalsIgnoreCase(attribute)
                || "lastModifiedTime".equalsIgnoreCase(attribute)
                || "lastAccessTime".equalsIgnoreCase(attribute)) {
            setFileTime(file, view, attribute, (FileTime) value, options);
        } else if ("extended".equalsIgnoreCase(view) && "extended".equalsIgnoreCase(attribute)) {
            @SuppressWarnings("unchecked")
            Map<String, byte[]> extensions = (Map<String, byte[]>) value;
            setFileExtensions(file, extensions, options);
        } else {
            setFileRawViewAttribute(file, view, attribute, value, options);
        }
    }

    protected void setFileTime(
            Path file, String view, String attribute, FileTime value, LinkOption... options)
            throws IOException {
        if (value == null) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("setFileTime({})[{}] {}:{}={}",
                    getServerSession(), file, view, attribute, value);
        }

        setFileRawViewAttribute(file, view, attribute, value, options);
    }

    protected void setFileRawViewAttribute(
            Path file, String view, String attribute, Object value, LinkOption... options)
            throws IOException {
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        accessor.setFileAttribute(
                getServerSession(), this, file, view, attribute, value, options);
    }

    protected void setFileOwnership(
            Path file, String attribute, Principal value, LinkOption... options)
            throws IOException {
        ServerSession serverSession = getServerSession();
        if (log.isDebugEnabled()) {
            log.debug("setFileOwnership({})[{}] {}={}", serverSession, file, attribute, value);
        }

        /*
         * Quoting from Javadoc of FileOwnerAttributeView#setOwner:
         *
         * To ensure consistent and correct behavior across platforms it is recommended that this method should only be
         * used to set the file owner to a user principal that is not a group.
         */
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        if ("owner".equalsIgnoreCase(attribute)) {
            accessor.setFileOwner(serverSession, this, file, value, options);
        } else if ("group".equalsIgnoreCase(attribute)) {
            accessor.setGroupOwner(serverSession, this, file, value, options);
        } else {
            throw new UnsupportedOperationException("Unknown ownership attribute: " + attribute);
        }
    }

    protected void setFileExtensions(
            Path file, Map<String, byte[]> extensions, LinkOption... options)
            throws IOException {
        if (GenericUtils.isEmpty(extensions)) {
            return;
        }

        /*
         * According to v3,4,5:
         *
         * Implementations SHOULD ignore extended data fields that they do not understand.
         *
         * But according to v6 (https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-28): Implementations MUST
         * return SSH_FX_UNSUPPORTED if there are any unrecognized extensions.
         */
        int version = getVersion();
        if (version < SftpConstants.SFTP_V6) {
            if (log.isDebugEnabled()) {
                log.debug("setFileExtensions({})[{}]: {}", getServerSession(), file, extensions);
            }
        } else {
            throw new UnsupportedOperationException("File extensions not supported");
        }
    }

    protected void setFilePermissions(
            Path file, Set<PosixFilePermission> perms, LinkOption... options)
            throws IOException {
        ServerSession serverSession = getServerSession();
        if (log.isTraceEnabled()) {
            log.trace("setFilePermissions({})[{}] {}", serverSession, file, perms);
        }

        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        accessor.setFilePermissions(
                serverSession, this, file, perms, options);
    }

    protected void setFileAccessControl(
            Path file, List<AclEntry> acl, LinkOption... options)
            throws IOException {
        ServerSession serverSession = getServerSession();
        if (log.isTraceEnabled()) {
            log.trace("setFileAccessControl({})[{}] {}", serverSession, file, acl);
        }

        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        accessor.setFileAccessControl(serverSession, this, file, acl, options);
    }

    protected void handleUnsupportedAttributes(Collection<String> attributes) {
        if (attributes.isEmpty()) {
            return;
        }

        String attrsList = GenericUtils.join(attributes, ',');
        UnsupportedAttributePolicy unsupportedAttributePolicy = getUnsupportedAttributePolicy();
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("Unsupported attributes: " + attrsList);
                break;
            case ThrowException:
                throw new UnsupportedOperationException("Unsupported attributes: " + attrsList);
            default:
                log.warn("Unknown policy for attributes=" + attrsList + ": " + unsupportedAttributePolicy);
        }
    }

    protected GroupPrincipal toGroup(Path file, GroupPrincipal name) throws IOException {
        try {
            SftpFileSystemAccessor accessor = getFileSystemAccessor();
            return accessor.resolveGroupOwner(getServerSession(), this, file, name);
        } catch (IOException e) {
            handleUserPrincipalLookupServiceException(GroupPrincipal.class, name.toString(), e);
            return null;
        }
    }

    protected UserPrincipal toUser(Path file, UserPrincipal name) throws IOException {
        try {
            SftpFileSystemAccessor accessor = getFileSystemAccessor();
            return accessor.resolveFileOwner(getServerSession(), this, file, name);
        } catch (IOException e) {
            handleUserPrincipalLookupServiceException(UserPrincipal.class, name.toString(), e);
            return null;
        }
    }

    protected void handleUserPrincipalLookupServiceException(
            Class<? extends Principal> principalType, String name, IOException e)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("handleUserPrincipalLookupServiceException(" + principalType.getSimpleName() + "[" + name + "]) details",
                    e);
        }

        /*
         * According to Javadoc:
         *
         * "Where an implementation does not support any notion of group or user then this method always throws
         * UserPrincipalNotFoundException."
         */
        UnsupportedAttributePolicy unsupportedAttributePolicy = getUnsupportedAttributePolicy();
        switch (unsupportedAttributePolicy) {
            case Ignore:
                break;
            case Warn:
                log.warn("handleUserPrincipalLookupServiceException(" + principalType.getSimpleName() + "[" + name + "])"
                         + " failed (" + e.getClass().getSimpleName() + "): " + e.getMessage());
                break;
            case ThrowException:
                throw e;
            default:
                log.warn("Unknown policy for principal=" + principalType.getSimpleName() + "[" + name + "]: "
                         + unsupportedAttributePolicy);
        }
    }

    protected Map<String, Object> readAttrs(Buffer buffer) throws IOException {
        return SftpHelper.readAttrs(buffer, getVersion());
    }

    /**
     * Makes sure that the local handle is not null and of the specified type
     *
     * @param  <H>                    The generic handle type
     * @param  handle                 The original handle id
     * @param  h                      The resolved {@link Handle} instance
     * @param  type                   The expected handle type
     * @return                        The cast type
     * @throws IOException            If a generic exception occurred
     * @throws FileNotFoundException  If the handle instance is {@code null}
     * @throws InvalidHandleException If the handle instance is not of the expected type
     */
    protected <H extends Handle> H validateHandle(String handle, Handle h, Class<H> type) throws IOException {
        if (h == null) {
            throw new NoSuchFileException(handle, handle, "No such current handle");
        }

        Class<?> t = h.getClass();
        if (!type.isAssignableFrom(t)) {
            throw new InvalidHandleException(handle, h, type);
        }

        return type.cast(h);
    }

    /**
     * Invoked when an exception was thrown due to the execution of some SFTP command
     *
     * @param  buffer      A {@link Buffer} to be used to build the status reply
     * @param  id          Command identifier
     * @param  e           Thrown exception
     * @param  cmd         The command that was attempted
     * @param  args        The relevant command arguments - <B>Note:</B> provided only for <U>logging</U> purposes and
     *                     subject to type and/or order change at any version
     * @throws IOException If failed to build and send the status buffer
     */
    protected void sendStatus(Buffer buffer, int id, Throwable e, int cmd, Object... args)
            throws IOException {
        SftpErrorStatusDataHandler handler = getErrorStatusDataHandler();
        int subStatus = handler.resolveSubStatus(this, id, e, cmd, args);
        String message = handler.resolveErrorMessage(this, id, e, subStatus, cmd, args);
        String lang = handler.resolveErrorLanguage(this, id, e, subStatus, cmd, args);
        sendStatus(buffer, id, subStatus, message, lang);
    }

    protected void sendStatus(Buffer buffer, int id, int substatus, String msg) throws IOException {
        sendStatus(buffer, id, substatus, (msg != null) ? msg : "", "");
    }

    protected void sendStatus(
            Buffer buffer, int id, int substatus, String msg, String lang)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("doSendStatus({})[id={}] SSH_FXP_STATUS (substatus={}, lang={}, msg={})",
                    getServerSession(), id, SftpConstants.getStatusName(substatus), lang, msg);
        }

        buffer.putByte((byte) SftpConstants.SSH_FXP_STATUS);
        buffer.putInt(id);
        buffer.putInt(substatus);
        buffer.putString(msg);
        buffer.putString(lang);
        send(buffer);
    }

    protected abstract Buffer prepareReply(Buffer buffer);

    protected abstract void send(Buffer buffer) throws IOException;

    protected Path resolveNormalizedLocation(String remotePath)
            throws IOException, InvalidPathException {
        Path resolvedPath = resolveFile(remotePath);
        return normalize(resolvedPath);
    }

    protected Path normalize(Path f) {
        if (f == null) {
            return null;
        }

        Path abs = f.isAbsolute() ? f : f.toAbsolutePath();
        return abs.normalize();
    }

    /**
     * @param  remotePath           The remote path - separated by '/'
     * @return                      The local {@link Path}
     * @throws IOException          If failed to resolve the local path
     * @throws InvalidPathException If bad local path specification
     */
    protected Path resolveFile(String remotePath)
            throws IOException, InvalidPathException {
        ServerSession serverSession = getServerSession();
        SftpFileSystemAccessor accessor = getFileSystemAccessor();
        Path localPath = accessor.resolveLocalFilePath(
                serverSession, this, getDefaultDirectory(), remotePath);
        if (log.isTraceEnabled()) {
            log.trace("resolveFile({}) {} => {}", serverSession, remotePath, localPath);
        }
        return localPath;
    }
}
