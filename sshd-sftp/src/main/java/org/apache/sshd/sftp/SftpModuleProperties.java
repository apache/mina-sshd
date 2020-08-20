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
package org.apache.sshd.sftp;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

import org.apache.sshd.common.Property;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.server.config.SshServerConfigFileReader;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.common.SftpHelper;
import org.apache.sshd.sftp.server.AbstractSftpSubsystemHelper;
import org.apache.sshd.sftp.server.SftpSubsystem;

/**
 * Configurable properties for sshd-sftp.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class SftpModuleProperties {

    /**
     * Used to indicate the {@link Charset} (or its name) for decoding referenced files/folders names - extracted from
     * the client session when 1st initialized.
     *
     * @see SftpClient#getNameDecodingCharset()
     * @see SftpClient#setNameDecodingCharset(Charset)
     */
    public static final Property<Charset> NAME_DECODING_CHARSET
            = Property.charset("sftp-name-decoding-charset", StandardCharsets.UTF_8);

    /**
     * Property that can be used on the {@link org.apache.sshd.common.FactoryManager} to control the internal timeout
     * used by the client to open a channel.
     */
    public static final Property<Duration> SFTP_CHANNEL_OPEN_TIMEOUT
            = Property.duration("sftp-channel-open-timeout", Duration.ofSeconds(15L));

    /**
     * See {@link org.apache.sshd.sftp.client.fs.SftpFileSystem}.
     */
    public static final Property<Integer> POOL_SIZE
            = Property.integer("sftp-fs-pool-size", 8);

    /**
     * See {@link org.apache.sshd.sftp.client.fs.SftpFileSystemProvider}.
     */
    public static final Property<Integer> READ_BUFFER_SIZE
            = Property.integer("sftp-fs-read-buffer-size");

    /**
     * See {@link org.apache.sshd.sftp.client.fs.SftpFileSystemProvider}.
     */
    public static final Property<Integer> WRITE_BUFFER_SIZE
            = Property.integer("sftp-fs-write-buffer-size");

    /**
     * See {@link org.apache.sshd.sftp.client.fs.SftpFileSystemProvider}.
     */
    public static final Property<Duration> CONNECT_TIME
            = Property.duration("sftp-fs-connect-time", Duration.ofSeconds(15L));

    /**
     * See {@link org.apache.sshd.sftp.client.fs.SftpFileSystemProvider}.
     */
    public static final Property<Duration> AUTH_TIME
            = Property.duration("sftp-fs-auth-time", Duration.ofSeconds(15L));

    /**
     * See {@link org.apache.sshd.sftp.client.fs.SftpFileSystemProvider}.
     */
    public static final Property<Charset> NAME_DECODER_CHARSET
            = Property.charset("sftp-fs-name-decoder-charset", StandardCharsets.UTF_8);

    /**
     * Property used to avoid large buffers when
     * {@link org.apache.sshd.sftp.client.impl.AbstractSftpClient#write(SftpClient.Handle, long, byte[], int, int)} is
     * invoked with a large buffer size.
     */
    public static final Property<Integer> WRITE_CHUNK_SIZE
            = Property.integer("sftp-client-write-chunk-size",
                    SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT - Long.SIZE);

    /**
     * Internal allocate buffer size when copying data to/from the channel
     */
    public static final Property<Integer> COPY_BUF_SIZE
            = Property.integer("sftp-channel-copy-buf-size", IoUtils.DEFAULT_COPY_SIZE);

    /**
     * Used to control whether to append the end-of-list indicator for SSH_FXP_NAME responses via
     * {@link SftpHelper#indicateEndOfNamesList(Buffer, int, PropertyResolver, boolean)} call, as indicated by
     * <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-9.4">SFTP v6 - section 9.4</A>
     */
    public static final Property<Boolean> APPEND_END_OF_LIST_INDICATOR
            = Property.bool("sftp-append-eol-indicator", true);

    /**
     * Whether to automatically follow symbolic links when resolving paths
     */
    public static final Property<Boolean> AUTO_FOLLOW_LINKS
            = Property.bool("sftp-auto-follow-links", true);

    /**
     * Allows controlling reports of which client extensions are supported (and reported via &quot;support&quot; and
     * &quot;support2&quot; server extensions) as a comma-separate list of names. <B>Note:</B> requires overriding the
     * {@link AbstractSftpSubsystemHelper#executeExtendedCommand(Buffer, int, String)} command accordingly. If empty
     * string is set then no server extensions are reported
     *
     * @see AbstractSftpSubsystemHelper#DEFAULT_SUPPORTED_CLIENT_EXTENSIONS
     */
    public static final Property<String> CLIENT_EXTENSIONS
            = Property.string("sftp-client-extensions");

    /**
     * Comma-separated list of which {@code OpenSSH} extensions are reported and what version is reported for each -
     * format: {@code name=version}. If empty value set, then no such extensions are reported. Otherwise, the
     * {@link AbstractSftpSubsystemHelper#DEFAULT_OPEN_SSH_EXTENSIONS} are used
     */
    public static final Property<String> OPENSSH_EXTENSIONS
            = Property.string("sftp-openssh-extensions");

    /**
     * Comma separate list of {@code SSH_ACL_CAP_xxx} names - where name can be without the prefix. If not defined then
     * {@link AbstractSftpSubsystemHelper#DEFAULT_ACL_SUPPORTED_MASK} is used
     */
    public static final Property<String> ACL_SUPPORTED_MASK
            = Property.string("sftp-acl-supported-mask");

    /**
     * Property that can be used to set the reported NL value. If not set, then {@link IoUtils#EOL} is used
     */
    public static final Property<String> NEWLINE_VALUE
            = Property.string("sftp-newline", IoUtils.EOL);

    /**
     * Force the use of a max. packet length for {@link AbstractSftpSubsystemHelper#doRead(Buffer, int)} protection
     * against malicious packets
     */
    public static final Property<Integer> MAX_READDATA_PACKET_LENGTH
            = Property.integer("sftp-max-readdata-packet-length", 63 * 1024);

    /**
     * Properties key for the maximum of available open handles per session.
     */
    public static final Property<Integer> MAX_OPEN_HANDLES_PER_SESSION
            = Property.integer("max-open-handles-per-session", Integer.MAX_VALUE);

    public static final int MIN_FILE_HANDLE_SIZE = 4; // ~uint32
    public static final int DEFAULT_FILE_HANDLE_SIZE = 16;
    public static final int MAX_FILE_HANDLE_SIZE = 64; // ~sha512

    /**
     * Size in bytes of the opaque handle value
     *
     * @see #DEFAULT_FILE_HANDLE_SIZE
     */
    public static final Property<Integer> FILE_HANDLE_SIZE
            = Property.validating(Property.integer("sftp-handle-size", DEFAULT_FILE_HANDLE_SIZE),
                    fhs -> {
                        ValidateUtils.checkTrue(fhs >= MIN_FILE_HANDLE_SIZE, "File handle size too small: %d", fhs);
                        ValidateUtils.checkTrue(fhs <= MAX_FILE_HANDLE_SIZE, "File handle size too big: %d", fhs);
                    });

    public static final int MIN_FILE_HANDLE_ROUNDS = 1;
    public static final int DEFAULT_FILE_HANDLE_ROUNDS = MIN_FILE_HANDLE_SIZE;
    public static final int MAX_FILE_HANDLE_ROUNDS = MAX_FILE_HANDLE_SIZE;

    /**
     * Max. rounds to attempt to create a unique file handle - if all handles already in use after these many rounds,
     * then an exception is thrown
     *
     * @see SftpSubsystem#generateFileHandle(Path)
     * @see #DEFAULT_FILE_HANDLE_ROUNDS
     */
    public static final Property<Integer> MAX_FILE_HANDLE_RAND_ROUNDS
            = Property.validating(
                    Property.integer("sftp-handle-rand-max-rounds", DEFAULT_FILE_HANDLE_ROUNDS),
                    fhrr -> {
                        ValidateUtils.checkTrue(fhrr >= MIN_FILE_HANDLE_ROUNDS, "File handle rounds too small: %d", fhrr);
                        ValidateUtils.checkTrue(fhrr <= MAX_FILE_HANDLE_ROUNDS, "File handle rounds too big: %d", fhrr);
                    });

    /**
     * Maximum amount of data allocated for listing the contents of a directory in any single invocation of
     * {@link SftpSubsystem#doReadDir(Buffer, int)}
     */
    public static final Property<Integer> MAX_READDIR_DATA_SIZE
            = Property.integer("sftp-max-readdir-data-size", 16 * 1024);

    /**
     * Force the use of a given sftp version
     */
    public static final Property<Integer> SFTP_VERSION
            = SshServerConfigFileReader.SFTP_FORCED_VERSION_PROP;

    private SftpModuleProperties() {
        throw new UnsupportedOperationException("No instance");
    }

}
