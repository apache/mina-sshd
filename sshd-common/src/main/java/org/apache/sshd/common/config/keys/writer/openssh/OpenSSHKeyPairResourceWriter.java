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
import org.apache.sshd.common.config.keys.loader.openssh.kdf.BCryptKdfOptions;
import org.apache.sshd.common.config.keys.writer.KeyPairResourceWriter;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.SecureByteArrayOutputStream;

/**
 * A {@link KeyPairResourceWriter} for writing keys in the modern OpenSSH format, using the OpenBSD bcrypt KDF for
 * passphrase-protected encrypted private keys.
 */
public class OpenSSHKeyPairResourceWriter implements KeyPairResourceWriter<OpenSSHKeyEncryptionContext> {

    public static final String DASHES = "-----"; //$NON-NLS-1$

    public static final int LINE_LENGTH = 70;

    public static final OpenSSHKeyPairResourceWriter INSTANCE = new OpenSSHKeyPairResourceWriter();

    private static final Pattern VERTICALSPACE = Pattern.compile("\\v"); //$NON-NLS-1$

    public OpenSSHKeyPairResourceWriter() {
        super();
    }

    @Override
    public void writePrivateKey(KeyPair key, String comment, OpenSSHKeyEncryptionContext options, OutputStream out)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(key, "Cannot write null key");
        String keyType = KeyUtils.getKeyType(key);
        if (GenericUtils.isEmpty(keyType)) {
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
        byte[] kdfOptions = GenericUtils.EMPTY_BYTE_ARRAY;
        try (SecureByteArrayOutputStream bytes = new SecureByteArrayOutputStream()) {
            write(bytes, OpenSSHKeyPairResourceParser.AUTH_MAGIC);
            bytes.write(0);
            if (opt != null) {
                KeyEncryptor encryptor = new KeyEncryptor(opt);
                opt.setPrivateKeyObfuscator(encryptor);

                byte[] encodedBytes = encryptor.applyPrivateKeyCipher(privateBytes, opt, true);
                Arrays.fill(privateBytes, (byte) 0);
                privateBytes = encodedBytes;
                kdfName = BCryptKdfOptions.NAME;
                kdfOptions = encryptor.getKdfOptions();
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

    public static OpenSSHKeyEncryptionContext determineEncryption(OpenSSHKeyEncryptionContext options) {
        CharSequence password = (options == null) ? null : options.getPassword();
        if (GenericUtils.isEmpty(password)) {
            return null;
        }

        for (int pos = 0, len = password.length(); pos < len; pos++) {
            char ch = password.charAt(pos);
            if (!Character.isWhitespace(ch)) {
                return options;
            }
        }

        return null;
    }

    public static byte[] encodePrivateKey(KeyPair key, String keyType, int blockSize, String comment)
            throws IOException, GeneralSecurityException {
        try (SecureByteArrayOutputStream out = new SecureByteArrayOutputStream()) {
            int check = new SecureRandom().nextInt();
            KeyEntryResolver.encodeInt(out, check);
            KeyEntryResolver.encodeInt(out, check);
            KeyEntryResolver.encodeString(out, keyType);
            @SuppressWarnings("unchecked") // Problem with generics
            PrivateKeyEntryDecoder<PublicKey, PrivateKey> encoder
                    = (PrivateKeyEntryDecoder<PublicKey, PrivateKey>) OpenSSHKeyPairResourceParser
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

    public static byte[] encodePublicKey(PublicKey key, String keyType)
            throws IOException, GeneralSecurityException {
        @SuppressWarnings("unchecked") // Problem with generics.
        PublicKeyEntryDecoder<PublicKey, ?> decoder
                = (PublicKeyEntryDecoder<PublicKey, ?>) KeyUtils.getPublicKeyEntryDecoder(keyType);
        if (decoder == null) {
            throw new GeneralSecurityException("Unknown key type: " + keyType);
        }
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            decoder.encodePublicKey(out, key);
            return out.toByteArray();
        }
    }

    public static void write(OutputStream out, byte[] bytes, int lineLength) throws IOException {
        byte[] encoded = Base64.getEncoder().encode(bytes);
        Arrays.fill(bytes, (byte) 0);
        try {
            int last = encoded.length;
            for (int i = 0; i < last; i += lineLength) {
                if ((i + lineLength) <= last) {
                    out.write(encoded, i, lineLength);
                } else {
                    out.write(encoded, i, last - i);
                }
                out.write('\n');
            }
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * {@inheritDoc}
     *
     * Writes the public key in the single-line OpenSSH format "key-type pub-key comment" without terminating line
     * ending. If the comment has multiple lines, only the first line is written.
     */
    @Override
    public void writePublicKey(PublicKey key, String comment, OutputStream out)
            throws IOException, GeneralSecurityException {
        StringBuilder b = new StringBuilder(82);
        PublicKeyEntry.appendPublicKeyEntry(b, key);
        // Append first line of comment - if available
        String line = firstLine(comment);
        if (GenericUtils.isNotEmpty(line)) {
            b.append(' ').append(line);
        }
        write(out, b.toString());
    }

    public static String firstLine(String text) {
        if (GenericUtils.isNotEmpty(text)) {
            Matcher m = VERTICALSPACE.matcher(text);
            if (m.find()) {
                return text.substring(0, m.start()).trim();
            }
        }

        return text;
    }

    public static void write(OutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * A key encryptor for modern-style OpenSSH private keys using the bcrypt KDF.
     */
    public static class KeyEncryptor extends AESPrivateKeyObfuscator {
        public static final int BCRYPT_SALT_LENGTH = 16;

        protected final OpenSSHKeyEncryptionContext options;

        private byte[] kdfOptions;

        public KeyEncryptor(OpenSSHKeyEncryptionContext options) {
            this.options = Objects.requireNonNull(options);
        }

        /**
         * Retrieves the KDF options used. Valid only after
         * {@link #deriveEncryptionKey(PrivateKeyEncryptionContext, int)} has been called.
         *
         * @return the number of KDF rounds applied
         */
        public byte[] getKdfOptions() {
            return kdfOptions;
        }

        /**
         * Derives an encryption key and set the IV on the {@code context} from the passphase provided by the context
         * using the OpenBSD {@link BCrypt} KDF.
         *
         * @param  context   for the encryption, provides the passphrase and transports other encryption-related
         *                   information including the IV
         * @param  keyLength number of key bytes to generate
         * @return           {@code keyLength} bytes to use as encryption key
         */
        @Override
        protected byte[] deriveEncryptionKey(PrivateKeyEncryptionContext context, int keyLength)
                throws IOException, GeneralSecurityException {
            byte[] iv = context.getInitVector();
            if (iv == null) {
                iv = generateInitializationVector(context);
            }

            byte[] salt = new byte[BCRYPT_SALT_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);

            byte[] kdfOutput = new byte[keyLength + iv.length];
            BCrypt bcrypt = new BCrypt();
            // "kdf" collects the salt and number of rounds; not sensitive data.
            try (ByteArrayOutputStream kdf = new ByteArrayOutputStream()) {
                int rounds = options.getKdfRounds();
                byte[] pwd = convert(options.getPassword());
                try {
                    bcrypt.pbkdf(pwd, salt, rounds, kdfOutput);
                } finally {
                    if (pwd != null) {
                        Arrays.fill(pwd, (byte) 0);
                    }
                }

                KeyEntryResolver.writeRLEBytes(kdf, salt);
                KeyEntryResolver.encodeInt(kdf, rounds);
                kdfOptions = kdf.toByteArray();
                context.setInitVector(Arrays.copyOfRange(kdfOutput, keyLength, kdfOutput.length));
                return Arrays.copyOf(kdfOutput, keyLength);
            } finally {
                Arrays.fill(kdfOutput, (byte) 0); // Contains the IV at the end
            }
        }

        protected byte[] convert(String password) {
            if (GenericUtils.isEmpty(password)) {
                return GenericUtils.EMPTY_BYTE_ARRAY;
            }

            char[] pass = password.toCharArray();
            ByteBuffer bytes;
            try {
                bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(pass));
            } finally {
                Arrays.fill(pass, '\0');
            }

            byte[] pwd = new byte[bytes.remaining()];
            bytes.get(pwd);
            if (bytes.hasArray()) {
                Arrays.fill(bytes.array(), (byte) 0);
            }
            return pwd;
        }
    }
}
