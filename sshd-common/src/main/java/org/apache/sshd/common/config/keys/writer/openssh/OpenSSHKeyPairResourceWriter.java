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

package org.apache.sshd.common.config.keys.writer.openssh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.CipherInformation;
import org.apache.sshd.common.config.keys.KeyEntryResolver;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PrivateKeyEntryDecoder;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryDecoder;
import org.apache.sshd.common.config.keys.loader.AESPrivateKeyObfuscator;
import org.apache.sshd.common.config.keys.loader.PrivateKeyEncryptionContext;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHParserContext;
import org.apache.sshd.common.config.keys.loader.openssh.kdf.BCrypt;
import org.apache.sshd.common.config.keys.writer.KeyPairResourceWriter;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.io.SecureByteArrayOutputStream;

/**
 * A {@link KeyPairResourceWriter} for writing keys in the modern OpenSSH format, using
 * the OpenBSD bcrypt KDF for passphrase-protected encrypted private keys.
 */
public class OpenSSHKeyPairResourceWriter implements KeyPairResourceWriter<OpenSSHKeyEncryptionContext> {

    private static final Pattern VERTICALSPACE = Pattern.compile("\\v"); //$NON-NLS-1$

    private static final String DASHES = "-----"; //$NON-NLS-1$

    private static final int LINE_LENGTH = 70;

    public OpenSSHKeyPairResourceWriter() {
       super();
    }

    @Override
    public void writePrivateKey(KeyPair key, String comment, OpenSSHKeyEncryptionContext options, SecureByteArrayOutputStream out)
            throws IOException, GeneralSecurityException {
        ValidateUtils.checkNotNull(key, "Cannot write null key");
        String keyType = KeyUtils.getKeyType(key);
        if (keyType == null) {
            throw new GeneralSecurityException("Unsupported key: " + key.getClass().getName());
        }
        OpenSSHKeyEncryptionContext opt = determineEncryption(options);
        // See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
        write(out, DASHES + OpenSSHKeyPairResourceParser.BEGIN_MARKER + DASHES); // $NON-NLS-1$
        // OpenSSH expects a single \n here, not a system line terminator!
        out.write('\n');
        String cipherName = OpenSSHParserContext.NONE_CIPHER;
        int blockSize = 8; // OpenSSH "none" cipher has block size 8
        if (opt != null) {
            cipherName = opt.getCipherFactoryName();
            CipherInformation spec = BuiltinCiphers.fromFactoryName(cipherName);
            if (spec == null) {
                // Internal error, no translation
                throw new IllegalArgumentException("Unsupported cipher " + cipherName); //$NON-NLS-1$
            }
            blockSize = spec.getCipherBlockSize();
        }
        byte[] privateBytes = encodePrivateKey(key, keyType, blockSize, comment);
        String kdfName = OpenSSHParserContext.NONE_CIPHER;
        byte[] kdfOptions = new byte[0];
        try (SecureByteArrayOutputStream bytes = new SecureByteArrayOutputStream()) {
            write(bytes, OpenSSHKeyPairResourceParser.AUTH_MAGIC);
            bytes.write(0);
            if (opt != null) {
                KeyEncryptor encryptor = new KeyEncryptor(opt);
                opt.setPrivateKeyObfuscator(encryptor);
                try {
                    byte[] encodedBytes = encryptor.applyPrivateKeyCipher(privateBytes, opt, true);
                    Arrays.fill(privateBytes, (byte) 0);
                    privateBytes = encodedBytes;
                    kdfName = "bcrypt"; //$NON-NLS-1$
                    kdfOptions = encryptor.getKdfOptions();
                } finally {
                    opt.clear();
                }
            }
            KeyEntryResolver.encodeString(bytes, cipherName);
            KeyEntryResolver.encodeString(bytes, kdfName);
            KeyEntryResolver.writeRLEBytes(bytes, kdfOptions);
            KeyEntryResolver.encodeInt(bytes, 1); // 1 key only.
            KeyEntryResolver.writeRLEBytes(bytes, encodePublicKey(key.getPublic(), keyType));
            KeyEntryResolver.writeRLEBytes(bytes, privateBytes);
            write(out, bytes.toByteArray(), LINE_LENGTH);
        } finally {
            Arrays.fill(privateBytes, (byte) 0);
        }
        write(out, DASHES + OpenSSHKeyPairResourceParser.END_MARKER + DASHES); // $NON-NLS-1$
        out.write('\n');
    }

    private static OpenSSHKeyEncryptionContext determineEncryption(OpenSSHKeyEncryptionContext options) {
        if (options == null) {
            return null;
        }
        char[] passphrase = options.getPassphrase();
        if (passphrase == null) {
            return null;
        }
        try {
            for (char ch : passphrase) {
                if (!Character.isWhitespace(ch)) {
                    return options;
                }
            }
        } finally {
            Arrays.fill(passphrase, '\000');
        }
        return null;
    }

    private static byte[] encodePrivateKey(KeyPair key, String keyType, int blockSize, String comment)
            throws IOException, GeneralSecurityException {
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            int check = new SecureRandom().nextInt();
            KeyEntryResolver.encodeInt(out, check);
            KeyEntryResolver.encodeInt(out, check);
            KeyEntryResolver.encodeString(out, keyType);
            @SuppressWarnings("unchecked") // Problem with generics
            PrivateKeyEntryDecoder<PublicKey, PrivateKey> encoder = (PrivateKeyEntryDecoder<PublicKey, PrivateKey>) OpenSSHKeyPairResourceParser
                    .getPrivateKeyEntryDecoder(keyType);
            if (encoder.encodePrivateKey(out, key.getPrivate(), key.getPublic()) == null) {
                throw new GeneralSecurityException("Cannot encode key of type " + keyType);
            }
            KeyEntryResolver.encodeString(out, comment == null ? "" : comment); //$NON-NLS-1$
            if (blockSize > 1) {
                // Padding
                int size = out.size();
                int extra = size % blockSize;
                if (extra != 0) {
                    for (int i = 1; i <= blockSize - extra; i++) {
                        out.write(i & 0xFF);
                    }
                }
            }
            return out.toByteArray();
        }
    }

    private static byte[] encodePublicKey(PublicKey key, String keyType) throws IOException, GeneralSecurityException {
        @SuppressWarnings("unchecked") // Problem with generics.
        PublicKeyEntryDecoder<PublicKey, ?> decoder = (PublicKeyEntryDecoder<PublicKey, ?>) KeyUtils
                .getPublicKeyEntryDecoder(keyType);
        if (decoder == null) {
            throw new GeneralSecurityException("Unknown key type: " + keyType);
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            decoder.encodePublicKey(out, key);
            return out.toByteArray();
        }
    }

    private static void write(OutputStream out, byte[] bytes, int lineLength) throws IOException {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        Arrays.fill(bytes, (byte) 0);
        int last = encoded.length;
        for (int i = 0; i < last; i += lineLength) {
            if (i + lineLength <= last) {
                out.write(encoded, i, lineLength);
            } else {
                out.write(encoded, i, last - i);
            }
            out.write('\n');
        }
        Arrays.fill(encoded, (byte) 0);
    }

    /**
     * {@inheritDoc}
     *
     * Writes the public key in the single-line OpenSSH format "key-type pub-key
     * comment" without terminating line ending. If the comment has multiple lines,
     * only the first line is written.
     */
    @Override
    public void writePublicKey(KeyPair key, String comment, OutputStream out)
            throws IOException, GeneralSecurityException {
        writePublicKey(key.getPublic(), comment, out);
    }

    /**
     * {@inheritDoc}
     *
     * Writes the public key in the single-line OpenSSH format "key-type pub-key
     * comment" without terminating line ending. If the comment has multiple lines,
     * only the first line is written.
     */
    @Override
    public void writePublicKey(PublicKey key, String comment, OutputStream out)
            throws IOException, GeneralSecurityException {
        StringBuilder b = new StringBuilder();
        PublicKeyEntry.appendPublicKeyEntry(b, key);
        // Append first line of comment
        if (comment != null) {
            String line = firstLine(comment);
            if (line != null && !line.isEmpty()) {
                b.append(' ').append(line);
            }
        }
        write(out, b.toString());
    }

    private static String firstLine(String text) {
        Matcher m = VERTICALSPACE.matcher(text);
        if (m.find()) {
            return text.substring(0, m.start());
        }
        return text;
    }

    private static void write(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * A key encryptor for modern-style OpenSSH private keys using the bcrypt KDF.
     */
    private static class KeyEncryptor extends AESPrivateKeyObfuscator {

        private static final int BCRYPT_SALT_LENGTH = 16;

        private final OpenSSHKeyEncryptionContext options;

        private byte[] kdfOptions;

        public KeyEncryptor(OpenSSHKeyEncryptionContext options) {
            this.options = Objects.requireNonNull(options);
        }

        /**
         * Retrieves the KDF options used. Valid only after
         * {@link #deriveEncryptionKey(PrivateKeyEncryptionContext, int)} has been
         * called.
         *
         * @return the number of KDF rounds applied
         */
        public byte[] getKdfOptions() {
            return kdfOptions;
        }

        /**
         * Derives an encryption key and set the IV on the {@code context} from the
         * passphase provided by the context using the OpenBSD {@link BCrypt} KDF.
         *
         * @param context   for the encryption, provides the passphrase and transports
         *                  other encryption-related information including the IV
         * @param keyLength number of key bytes to generate
         * @return {@code keyLength} bytes to use as encryption key
         */
        @Override
        protected byte[] deriveEncryptionKey(PrivateKeyEncryptionContext context, int keyLength)
                throws GeneralSecurityException {
            byte[] iv = context.getInitVector();
            if (iv == null) {
                iv = generateInitializationVector(context);
            }
            byte[] kdfOutput = new byte[keyLength + iv.length];
            byte[] salt = new byte[BCRYPT_SALT_LENGTH];
            BCrypt bcrypt = new BCrypt();
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            int rounds = options.getKdfRounds();
            byte[] pwd = null;
            byte[] result = null;
            // "kdf" collects the salt and number of rounds; not sensitive data.
            try (ByteArrayOutputStream kdf = new ByteArrayOutputStream()) {
                pwd = convert(options.getPassphrase());
                bcrypt.pbkdf(pwd, salt, rounds, kdfOutput);
                KeyEntryResolver.writeRLEBytes(kdf, salt);
                KeyEntryResolver.encodeInt(kdf, rounds);
                kdfOptions = kdf.toByteArray();
                context.setInitVector(Arrays.copyOfRange(kdfOutput, keyLength, kdfOutput.length));
                result = Arrays.copyOf(kdfOutput, keyLength);
            } catch (IOException impossible) {
                // Never occurs with a ByteArrayOutputStream
            } finally {
                Arrays.fill(kdfOutput, (byte) 0); // Contains the IV at the end
                if (pwd != null) {
                    Arrays.fill(pwd, (byte) 0);
                }
            }
            return result;
        }

        private byte[] convert(char[] pass) {
            if (pass == null) {
                return new byte[0];
            }
            ByteBuffer bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(pass));
            byte[] pwd = new byte[bytes.remaining()];
            bytes.get(pwd);
            if (bytes.hasArray()) {
                Arrays.fill(bytes.array(), (byte) 0);
            }
            Arrays.fill(pass, '\000');
            return pwd;
        }
    }
}
