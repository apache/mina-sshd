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
package org.apache.sshd.server.keyprovider;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamConstants;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKeyPairResourceParser;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.session.SessionContext;

/**
 * A simple implementation of an {@link AbstractGeneratorHostKeyProvider} that writes and reads host keys using the
 * OpenSSH file format. Legacy keys written by earlier implementations used Java serialization. De-serializing is
 * restricted to a small number of classes known to exist in serialized {@link KeyPair}s.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SimpleGeneratorHostKeyProvider extends AbstractGeneratorHostKeyProvider {

    public SimpleGeneratorHostKeyProvider() {
        super();
    }

    public SimpleGeneratorHostKeyProvider(Path path) {
        setPath(path);
    }

    @Override
    protected Iterable<KeyPair> doReadKeyPairs(SessionContext session, NamedResource resourceKey, InputStream inputStream)
            throws IOException, GeneralSecurityException {
        try (BufferedInputStream in = new BufferedInputStream(inputStream)) {
            if (isJavaSerialization(in, resourceKey)) {
                try (ObjectInputStream r = new ValidatingObjectInputStream(in)) {
                    return Collections.singletonList((KeyPair) r.readObject());
                } catch (ClassNotFoundException e) {
                    throw new InvalidKeySpecException(
                            "Cannot de-serialize " + resourceKey + ": missing classes: " + e.getMessage(), e);
                }
            } else {
                OpenSSHKeyPairResourceParser reader = new OpenSSHKeyPairResourceParser();
                return reader.loadKeyPairs(null, resourceKey, null, in);
            }
        }
    }

    private boolean isJavaSerialization(BufferedInputStream in, NamedResource resourceKey) throws IOException {
        in.mark(2);
        try {
            byte[] magicBytes = new byte[2];
            int length = in.read(magicBytes);
            if (length != 2) {
                throw new StreamCorruptedException("File " + resourceKey + " is not a host key");
            }
            short magic = (short) (((magicBytes[0] & 0xFF) << 8) | (magicBytes[1] & 0xFF));
            return magic == ObjectStreamConstants.STREAM_MAGIC;
        } finally {
            in.reset();
        }
    }

    @Override
    protected void doWriteKeyPair(NamedResource resourceKey, KeyPair kp, OutputStream outputStream)
            throws IOException, GeneralSecurityException {
        OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();
        try (OutputStream out = outputStream) {
            writer.writePrivateKey(kp, "host key", null, out);
        }
    }

    private static class ValidatingObjectInputStream extends ObjectInputStream {

        private static final Set<String> ALLOWED = new HashSet<>();

        static {
            ALLOWED.add("[B"); // byte[], used in BC EC key serialization

            ALLOWED.add("java.lang.Enum");
            ALLOWED.add("java.lang.Number");
            ALLOWED.add("java.lang.String");

            ALLOWED.add("java.math.BigInteger"); // Used in BC DSA/RSA

            ALLOWED.add("java.security.KeyPair");
            ALLOWED.add("java.security.PublicKey");
            ALLOWED.add("java.security.PrivateKey");
            ALLOWED.add("java.security.KeyRep");
            ALLOWED.add("java.security.KeyRep$Type");

            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey");
            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey");
            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey");
            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey");
            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey");
            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey");
            ALLOWED.add("org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey");

            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey");
            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey");
            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey");
            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey");
            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey");
            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey");
            ALLOWED.add("com.android.org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey");

            // net.i2p EdDSA keys cannot be serialized anyway; so no need to whitelist any of their classes.
            // They use the default serialization, which writes a great many different classes, but at least
            // one of them does not implement Serializable, and thus writing runs into a NotSerializableException.
        }

        ValidatingObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
            validate(desc.getName());
            return super.resolveClass(desc);
        }

        private void validate(String className) throws IOException {
            if (!ALLOWED.contains(className)) {
                throw new IOException(className + " blocked for deserialization");
            }
        }
    }

}
