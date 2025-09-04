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
package org.apache.sshd.common.session.filters;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.cipher.CipherNone;
import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filter that decrypts incoming packets and encrypts outgoing ones.
 */
public class CryptFilter extends IoFilter implements CryptStatisticsProvider {

    /**
     * The maximum padding length we use. RFC 4253: at least 4 bytes padding, at most 255 bytes.
     * <p>
     * Keep the padding size &lt;= 127, though: JSch has a bug where it reads the pad byte as a signed value when
     * compression is used!
     * </p>
     */
    public static final int MAX_PADDING = 127;

    /**
     * An arbitrary constant >= the largest authentication tag size we will ever have.
     */
    public static final int MAX_TAG_LENGTH = 64;

    private static final Logger LOG = LoggerFactory.getLogger(CryptFilter.class);

    // The minimum value for the packet length field of a valid SSH packet:
    // - 1 byte padding count
    // - 1 byte payload
    // - 4 bytes padding
    // Since all ciphers, including the none cipher, have a block size of at least 8, we need to
    // have at least 8 bytes if the length itself is not encrypted, or 12 if it is. (Even if a
    // zero-length payload was allowed, it would be 8 or 12.) So in practice the minimum length
    // is 8 bytes.
    private static final int MIN_PACKET_LENGTH = 8;

    private static final int UNKNOWN_PACKET_LENGTH = -1;

    private final AtomicReference<Settings> decryption = new AtomicReference<>();

    private final AtomicReference<Settings> encryption = new AtomicReference<>();

    private final AtomicReference<Counters> inCounts = new AtomicReference<>();

    private final AtomicReference<Counters> outCounts = new AtomicReference<>();

    private final DecryptionHandler input = new DecryptionHandler();

    private final EncryptionHandler output = new EncryptionHandler();

    private final CopyOnWriteArrayList<EncryptionListener> listeners = new CopyOnWriteArrayList<>();

    private Random random = ThreadLocalRandom.INSTANCE;

    private Session session;

    public CryptFilter() {
        decryption.set(new Settings(null, null));
        encryption.set(new Settings(null, null));
        inCounts.set(new Counters());
        outCounts.set(new Counters());
    }

    public void setRandom(Random random) {
        this.random = random;
    }

    public void setSession(Session session) {
        this.session = session;
    }

    @Override
    public InputHandler in() {
        return input;
    }

    @Override
    public OutputHandler out() {
        return output;
    }

    public void resetInputCounters() {
        inCounts.set(new Counters());
    }

    public void resetOutputCounters() {
        outCounts.set(new Counters());
    }

    @Override
    public Counters getInputCounters() {
        return inCounts.get();
    }

    @Override
    public Counters getOutputCounters() {
        return outCounts.get();
    }

    public void setInput(Settings settings, boolean resetSequence) {
        decryption.set(Objects.requireNonNull(settings));
        if (resetSequence) {
            input.sequenceNumber.set(0);
        }
    }

    public void setOutput(Settings settings, boolean resetSequence) {
        encryption.set(Objects.requireNonNull(settings));
        if (resetSequence) {
            output.sequenceNumber.set(0);
        }
    }

    public Settings getInputSettings() {
        return decryption.get();
    }

    public Settings getOutputSettings() {
        return encryption.get();
    }

    @Override
    public long getLastInputSequenceNumber() {
        return (input.sequenceNumber.get() - 1) & 0xFFFF_FFFFL;
    }

    @Override
    public long getInputSequenceNumber() {
        return input.sequenceNumber.get() & 0xFFFF_FFFFL;
    }

    @Override
    public long getOutputSequenceNumber() {
        return output.sequenceNumber.get() & 0xFFFF_FFFFL;
    }

    @Override
    public boolean isSecure() {
        return decryption.get().isSecure() && encryption.get().isSecure();
    }

    public void addEncryptionListener(EncryptionListener listener) {
        listeners.addIfAbsent(Objects.requireNonNull(listener));
    }

    public void removeEncryptionListener(EncryptionListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    public interface EncryptionListener {

        void aboutToEncrypt(Readable buffer, long sequenceNumber);

    }

    private abstract class WithSequenceNumber {

        final AtomicInteger sequenceNumber = new AtomicInteger();

        WithSequenceNumber() {
            super();
        }
    }

    private class DecryptionHandler extends WithSequenceNumber implements InputHandler {

        // Work buffer accumulating incoming data until we have a full SSH packet. Once we have, the decoded part of
        // this buffer is passed on. Then the buffer is compacted and we start handling the next packet.
        private Buffer buffer = new ByteArrayBuffer();

        private int packetLength = UNKNOWN_PACKET_LENGTH;

        // Set if we get an invalid packet length. If we do, we keep on requesting more data, and then fail later by
        // throwing this exception, if set. The connection is supposed to be closed then.
        private SshException discarding;

        DecryptionHandler() {
            super();
        }

        @Override
        public synchronized void received(Readable message) throws Exception {
            buffer.putBuffer(message);
            // If we have less than Integer.BYTES bytes, we cannot possible get a packet length.
            // Higher levels are responsible to close the connection if we never get data.
            while (buffer.available() >= Integer.BYTES) {
                Settings settings = decryption.get();
                Cipher cipher = settings.getCipher();
                boolean isAead = cipher != null && settings.isAead();
                boolean isEtm = settings.isEtm();
                int cipherSize = cipher == null ? 8 : cipher.getCipherBlockSize();
                if (packetLength < 0) {
                    // We don't know the packet length yet.
                    assert buffer.rpos() == 0;
                    // Need: Integer.BYTES if packet length is unencrypted or AEAD cipher is used; cipher's block size
                    // otherwise
                    int need = Integer.BYTES;
                    if (cipher != null && !isEtm && !isAead) {
                        need = cipherSize;
                    }
                    if (buffer.available() < need) {
                        // Wait for more data
                        break;
                    }
                    if (cipher != null) {
                        // Decrypt the length.
                        byte[] data = buffer.array();
                        if (isAead) {
                            cipher.updateAAD(data, 0, Integer.BYTES);
                        } else if (!isEtm) {
                            cipher.update(data, 0, need);
                        }
                    }
                    packetLength = buffer.getInt();

                    // Validate the packet length
                    boolean lengthOK = true;
                    if (packetLength < MIN_PACKET_LENGTH
                            || packetLength > (8 * SshConstants.SSH_REQUIRED_PAYLOAD_PACKET_LENGTH_SUPPORT)) {
                        LOG.warn("received({}) Error decoding packet (invalid length): {}", session, packetLength);
                        lengthOK = false;
                    } else if (((packetLength + ((isAead || isEtm) ? 0 : Integer.BYTES)) & (cipherSize - 1)) != 0) {
                        // Note: we assume cipherSize is a power of two.
                        LOG.warn("received({}) Error decoding packet(padding; not multiple of {}): {}", session, cipherSize,
                                packetLength);
                        lengthOK = false;
                    }
                    if (!lengthOK) {
                        // Mitigation against CVE-2008-5161 AKA CPNI-957037: make any disconnections due to decoding
                        // errors indistinguishable from failed MAC checks.
                        //
                        // If we disconnect here, a client may still deduce (since it sent only one block) that the
                        // length check failed. So we keep on requesting more data and fail later. OpenSSH actually
                        // discards the next 256kB of data, but in fact any number of bytes will do.
                        //
                        // Remember the exception, continue requiring an arbitrary number of bytes, and throw the
                        // exception later.
                        discarding = new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                                "Invalid packet length: " + packetLength);
                        packetLength = buffer.available() + (2 + random.random(20)) * cipherSize;
                        // Round up to the next larger multiple of the block size
                        packetLength = (packetLength + (cipherSize - 1)) & ~(cipherSize - 1);
                        if (!isAead && !isEtm) {
                            packetLength -= Integer.BYTES;
                        }
                        LOG.warn("received({}) Invalid packet length; requesting {} bytes before disconnecting",
                                session, packetLength - buffer.available());
                    }
                }
                assert buffer.rpos() == Integer.BYTES;
                // We have a length here.
                if (buffer.available() < packetLength + settings.getTagSize()) {
                    // Need more data
                    break;
                }
                // Decrypt the packet. We allow cipher == null && mac != null.
                byte[] data = buffer.array();
                int bytes;
                if (isAead) {
                    // Packet length is handled by AAD
                    bytes = packetLength;
                    cipher.update(data, Integer.BYTES, bytes);
                } else if (isEtm) {
                    // Packet length is unencrypted
                    bytes = packetLength;
                    checkMac(data, 0, bytes + Integer.BYTES, settings.getMac());
                    if (cipher != null) {
                        cipher.update(data, Integer.BYTES, bytes);
                    }
                } else {
                    bytes = packetLength + Integer.BYTES;
                    if (cipher != null) {
                        // First block was decrypted when we got the packet length.
                        cipher.update(data, cipherSize, bytes - cipherSize);
                    }
                    checkMac(data, 0, bytes, settings.getMac());
                }

                // Mitigation against CVE-2008-5161 AKA CPNI-957037. But is is highly unlikely that we pass the AAD or
                // MAC checks above.
                if (discarding != null) {
                    throw discarding;
                }

                inCounts.get().update(bytes / cipherSize, bytes);
                sequenceNumber.incrementAndGet();

                int endOfDataReceived = buffer.wpos();
                int afterPacket = packetLength + Integer.BYTES + settings.getTagSize();

                int padding = buffer.getUByte();
                if (padding < 4) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                            "Invalid packet padding, must have at least 4 padding bytes according to RFC 4253, got " + padding);
                }
                int endOfPayload = packetLength + Integer.BYTES - padding;
                if (endOfPayload <= buffer.rpos()) {
                    // A valid SSH packet never has an empty payload; there's at the very least a single byte containing
                    // the command code.
                    throw new SshException(SshConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                            "Invalid packet payload length " + (buffer.rpos() - endOfPayload));
                }
                // Pass it on (directly the slice of this buffer)
                buffer.wpos(endOfPayload);
                owner().passOn(buffer);

                // Reset buffer positions
                buffer.rpos(afterPacket);
                buffer.wpos(endOfDataReceived);
                buffer.compact();
                packetLength = UNKNOWN_PACKET_LENGTH;
            }
        }

        private void checkMac(byte[] data, int offset, int length, Mac mac) throws Exception {
            if (mac != null) {
                mac.updateUInt(sequenceNumber.get());
                mac.update(data, offset, length);
                byte[] x = mac.doFinal();
                if (!Mac.equals(x, 0, data, offset + length, x.length)) {
                    throw new SshException(SshConstants.SSH2_DISCONNECT_MAC_ERROR, "MAC error");
                }
            }
        }
    }

    private class EncryptionHandler extends WithSequenceNumber implements OutputHandler {

        EncryptionHandler() {
            super();
        }

        @Override
        public synchronized IoWriteFuture send(int cmd, Buffer message) throws IOException {
            Buffer encrypted = message;
            if (encrypted != null) {
                try {
                    listeners.forEach(listener -> listener.aboutToEncrypt(message, getOutputSequenceNumber()));
                    encrypted = encode(cmd, message);
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IOException(e.getMessage(), e);
                }
            }
            return owner().send(cmd, encrypted);
        }

        private Buffer encode(int cmd, Buffer packet) throws Exception {
            Settings settings = encryption.get();
            Cipher cipher = settings.getCipher();
            boolean isAead = cipher != null && settings.isAead();
            boolean isEtm = settings.isEtm();
            int cipherSize = cipher == null ? 8 : cipher.getCipherBlockSize();
            // We assume cipherSize is a power of two.
            int rpos = packet.rpos();
            int length = packet.available();
            int start = rpos - SshConstants.SSH_PACKET_HEADER_LEN;
            if (start < 0) {
                throw new IllegalArgumentException("Message is not an SSH packet buffer; need 5 spare bytes at the front");
            }
            int pad = paddingLength(cmd, length, cipherSize, !isAead && !isEtm);
            // RFC 4253: at least 4 bytes padding, at most 255 bytes
            if (pad < 4 || pad > MAX_PADDING) {
                throw new IllegalStateException("Invalid packet length computed: " + pad + " not in range [4..255]");
            }
            packet.wpos(start);
            packet.putUInt(1L + length + pad);
            packet.putByte((byte) pad);
            // Ensure there's enough space, then fill in the padding
            int tagSize = settings.getTagSize();
            packet.wpos(packet.wpos() + length + pad + tagSize);
            byte[] data = packet.array();
            random.fill(data, packet.wpos() - tagSize - pad, pad);
            int bytes;
            if (isAead) {
                cipher.updateAAD(data, start, Integer.BYTES);
                bytes = length + pad + 1;
                cipher.update(data, start + Integer.BYTES, bytes);
            } else if (isEtm) {
                bytes = length + pad + 1;
                if (cipher != null) {
                    cipher.update(data, start + Integer.BYTES, bytes);
                }
                appendMac(data, start, packet.wpos() - tagSize, settings.getMac());
            } else {
                appendMac(data, start, packet.wpos() - tagSize, settings.getMac());
                bytes = length + pad + SshConstants.SSH_PACKET_HEADER_LEN;
                if (cipher != null) {
                    cipher.update(data, start, bytes);
                }
            }
            outCounts.get().update(bytes / cipherSize, bytes);
            sequenceNumber.incrementAndGet();

            packet.rpos(start);
            return packet;
        }

        private int paddingLength(int cmd, int payloadLength, int blockSize, boolean includePacketLength) {
            int toEncrypt = payloadLength + 1; // For the padding count itself.
            if (includePacketLength) {
                toEncrypt += Integer.BYTES;
            }
            // RFC 4253: at least 4, at most 255 bytes.
            int minPadding = 4;
            int maxPadding = MAX_PADDING;
            // Minor layering break here: always pad messages that might carry user passwords with at least 64 bytes
            // to prevent that traffic analysis might make guesses about password lengths.
            if (cmd >= SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST && cmd <= SshConstants.SSH_MSG_USERAUTH_GSSAPI_MIC) {
                minPadding = 64; // Must be smaller than MAX_PADDING, of course
            } else if (payloadLength < 16) {
                // For very small data packets (such as single keystrokes) ensure that we don't grow too much.
                // 16 is a bit arbitrary; a single keystroke in an interactive session is 10 bytes (SSH_MSG_CHANNEL_DATA
                // + channel id + data length + 1 byte data), and so are the messages from the "ping@openssh.com"
                // extension used for keystroke obfuscation (SSH_MSG_PING + data length + "PING!").
                maxPadding = 64;
            }
            int pad = minPadding;
            // For low-level messages, do not add extra padding.
            if (cmd >= SshConstants.SSH_MSG_KEXINIT) {
                // RFC 4253: variable amounts of random padding may help thwart traffic analysis. We don't need a secure
                // random for this. Note that the padding can only randomize message size on the wire in quanta of
                // blockSize. It's a bit unclear how effective this may be against traffic analysis.
                pad = minPadding + random.random(maxPadding + 1 - minPadding);
            }
            // Now pad is in the range [4..MAX_PADDING]
            int totalLength = toEncrypt + pad;
            // Adjust pad such that totalLength is a multiple of the blockSize, and is still larger than 4.
            pad = (totalLength & ~(blockSize - 1)) - toEncrypt;
            if (pad < 4) {
                pad += blockSize;
            }
            return pad;
        }

        private void appendMac(byte[] data, int start, int end, Mac mac) throws Exception {
            if (mac != null) {
                mac.updateUInt(sequenceNumber.get());
                mac.update(data, start, end - start);
                mac.doFinal(data, end);
            }
        }
    }

    public static class Settings {

        private final Cipher cipher;

        private final Mac mac;

        private final int tagSize;

        private final boolean etm;

        private final boolean aead;

        public Settings(Cipher cipher, Mac mac) {
            this.cipher = cipher;
            this.mac = mac;
            int tagSz = 0;
            if (cipher != null) {
                tagSz += cipher.getAuthenticationTagSize();
            }
            aead = tagSz > 0;
            if (aead && mac != null) {
                throw new IllegalStateException("AEAD cipher " + cipher + " must not have a MAC: " + mac);
            }
            if (mac != null) {
                tagSz += mac.getBlockSize();
            }
            tagSize = tagSz;
            etm = mac != null && mac.isEncryptThenMac();
        }

        public Cipher getCipher() {
            return cipher;
        }

        public Mac getMac() {
            return mac;
        }

        public int getTagSize() {
            return tagSize;
        }

        public boolean isEtm() {
            return etm;
        }

        public boolean isAead() {
            return aead;
        }

        public boolean isSecure() {
            return cipher != null && !(cipher instanceof CipherNone) && tagSize > 0;
        }
    }

    public static class Counters implements CryptStatisticsProvider.Counters {

        private AtomicLong bytes = new AtomicLong();

        private AtomicLong blocks = new AtomicLong();

        private AtomicLong packets = new AtomicLong();

        Counters() {
            super();
        }

        public void update(int blocks, int bytes) {
            this.blocks.addAndGet(blocks);
            this.bytes.addAndGet(bytes);
            this.packets.incrementAndGet();
        }

        @Override
        public long getBytes() {
            return bytes.get();
        }

        @Override
        public long getBlocks() {
            return blocks.get();
        }

        @Override
        public long getPackets() {
            return packets.get();
        }
    }
}
