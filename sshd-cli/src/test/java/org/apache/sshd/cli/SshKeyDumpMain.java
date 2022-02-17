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

package org.apache.sshd.cli;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.io.PathUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.putty.PuttyKeyPairResourceParser;
import org.apache.sshd.putty.PuttyKeyUtils;
import org.apache.sshd.server.config.keys.AuthorizedKeysAuthenticator;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum SshKeyDumpMain {
    /* Utility class */;

    ////////////////////////////////////////////////////////////////////////////////////////////////

    public static void dumpRSAPublicKey(RSAPublicKey key, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("e: ").append(Objects.toString(key.getPublicExponent(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("n: ").append(Objects.toString(key.getModulus(), null))
                .append(System.lineSeparator());
    }

    public static void dumpRSAPrivateKey(RSAPrivateKey key, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("d: ").append(Objects.toString(key.getPrivateExponent(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("n: ").append(Objects.toString(key.getModulus(), null))
                .append(System.lineSeparator());
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey crt = RSAPrivateCrtKey.class.cast(key);
            stdout.append(indent)
                    .append("e: ").append(Objects.toString(crt.getPublicExponent(), null))
                    .append(System.lineSeparator());
            stdout.append(indent)
                    .append("P: ").append(Objects.toString(crt.getPrimeP(), null))
                    .append(System.lineSeparator());
            stdout.append(indent)
                    .append("Q: ").append(Objects.toString(crt.getPrimeQ(), null))
                    .append(System.lineSeparator());
            stdout.append(indent)
                    .append("expP: ").append(Objects.toString(crt.getPrimeExponentP(), null))
                    .append(System.lineSeparator());
            stdout.append(indent)
                    .append("expQ: ").append(Objects.toString(crt.getPrimeExponentQ(), null))
                    .append(System.lineSeparator());
            stdout.append(indent)
                    .append("coefficient: ").append(Objects.toString(crt.getCrtCoefficient(), null))
                    .append(System.lineSeparator());
        }
    }

    public static void dumpDSAParams(DSAParams params, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("G: ").append(Objects.toString(params.getG(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("P: ").append(Objects.toString(params.getP(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("Q: ").append(Objects.toString(params.getQ(), null))
                .append(System.lineSeparator());
    }

    public static void dumpDSAPublicKey(DSAPublicKey key, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("Y: ").append(Objects.toString(key.getY(), null))
                .append(System.lineSeparator());
        dumpDSAParams(key.getParams(), indent + "    ",
                stdout.append(indent).append("params:").append(System.lineSeparator()));
    }

    public static void dumpDSAPrivateKey(DSAPrivateKey key, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("X: ").append(Objects.toString(key.getX(), null))
                .append(System.lineSeparator());
        dumpDSAParams(key.getParams(), indent + "    ",
                stdout.append(indent).append("params:").append(System.lineSeparator()));
    }

    public static void dumpECPoint(ECPoint point, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("X: ").append(Objects.toString(point.getAffineX(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("Y: ").append(Objects.toString(point.getAffineY(), null))
                .append(System.lineSeparator());
    }

    public static void dumpECField(ECField field, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("size: ").append(Integer.toString(field.getFieldSize()))
                .append(System.lineSeparator());
    }

    public static void dumpEllipticCurve(EllipticCurve curve, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("A: ").append(Objects.toString(curve.getA(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("B: ").append(Objects.toString(curve.getB(), null))
                .append(System.lineSeparator());
        BufferUtils.appendHex(stdout.append(indent).append("seed: "), ' ', curve.getSeed()).append(System.lineSeparator());
        dumpECField(curve.getField(), indent + "    ",
                stdout.append(indent).append("field:").append(System.lineSeparator()));
    }

    public static void dumpECParameterSpec(ECParameterSpec spec, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("order: ").append(Objects.toString(spec.getOrder(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("cofactor: ").append(Integer.toString(spec.getCofactor()))
                .append(System.lineSeparator());
        dumpEllipticCurve(spec.getCurve(), indent + "    ",
                stdout.append(indent).append("curve:").append(System.lineSeparator()));
        dumpECPoint(spec.getGenerator(), indent + "    ",
                stdout.append(indent).append("generator:").append(System.lineSeparator()));
    }

    public static void dumpECPublicKey(ECPublicKey key, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("W: ").append(Objects.toString(key.getW(), null))
                .append(System.lineSeparator());
        dumpECParameterSpec(key.getParams(), indent + "    ",
                stdout.append(indent).append("params:").append(System.lineSeparator()));
    }

    public static void dumpECPrivateKey(ECPrivateKey key, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("S: ").append(Objects.toString(key.getS(), null))
                .append(System.lineSeparator());
        dumpECParameterSpec(key.getParams(), indent + "    ",
                stdout.append(indent).append("params:").append(System.lineSeparator()));
    }

    public static void dumpEdDSAField(Field field, CharSequence indent, Appendable stdout) throws IOException {
        stdout.append(indent)
                .append("Q: ").append(Objects.toString(field.getQ(), null))
                .append(System.lineSeparator());
    }

    public static void dumpEdDSACurve(Curve curve, CharSequence indent, Appendable stdout) throws IOException {
        dumpEdDSAField(curve.getField(), indent + "    ",
                stdout.append(indent).append("field: ").append(System.lineSeparator()));
        stdout.append(indent)
                .append("D: ").append(Objects.toString(curve.getD(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("I: ").append(Objects.toString(curve.getI(), null))
                .append(System.lineSeparator());
    }

    public static void dumpEdDSAGroupElement(GroupElement group, CharSequence indent, Appendable stdout) throws IOException {
        dumpEdDSACurve(group.getCurve(), indent + "    ",
                stdout.append(indent).append("curve:").append(System.lineSeparator()));
        stdout.append(indent)
                .append("X: ").append(Objects.toString(group.getX(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("Y: ").append(Objects.toString(group.getY(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("Z: ").append(Objects.toString(group.getZ(), null))
                .append(System.lineSeparator());
        stdout.append(indent)
                .append("T: ").append(Objects.toString(group.getT(), null))
                .append(System.lineSeparator());
    }

    public static void dumpEdDSAParameterSpec(EdDSAParameterSpec params, CharSequence indent, Appendable stdout)
            throws IOException {
        dumpEdDSAGroupElement(params.getB(), indent + "    ",
                stdout.append(indent).append("B:").append(System.lineSeparator()));
        stdout.append(indent)
                .append("hashAlgorith,: ").append(params.getHashAlgorithm())
                .append(System.lineSeparator());
        dumpEdDSACurve(params.getCurve(), indent + "    ",
                stdout.append(indent).append("curve:").append(System.lineSeparator()));
    }

    public static void dumpEdDSAPublicKey(EdDSAPublicKey key, CharSequence indent, Appendable stdout) throws IOException {
        dumpEdDSAGroupElement(key.getA(), indent + "    ",
                stdout.append(indent).append("A:").append(System.lineSeparator()));
        dumpEdDSAParameterSpec(key.getParams(), indent + "    ",
                stdout.append(indent).append("params:").append(System.lineSeparator()));
    }

    public static void dumpEdDSAPrivateKey(EdDSAPrivateKey key, CharSequence indent, Appendable stdout) throws IOException {
        dumpEdDSAGroupElement(key.getA(), indent + "    ",
                stdout.append(indent).append("A:").append(System.lineSeparator()));
        BufferUtils.appendHex(stdout.append(indent).append("seed: "), ' ', key.getSeed()).append(System.lineSeparator());
        BufferUtils.appendHex(stdout.append(indent).append("H: "), ' ', key.getH()).append(System.lineSeparator());
        dumpEdDSAParameterSpec(key.getParams(), indent + "    ",
                stdout.append(indent).append("params:").append(System.lineSeparator()));
    }

    public static void dumpPublicKey(PublicKey key, CharSequence indent, Appendable stdout, Appendable stderr)
            throws IOException {
        if (key instanceof RSAPublicKey) {
            dumpRSAPublicKey(
                    RSAPublicKey.class.cast(key), indent + "    ",
                    stdout.append(indent).append("RSA").append(System.lineSeparator()));
            return;
        } else if (key instanceof DSAPublicKey) {
            dumpDSAPublicKey(
                    DSAPublicKey.class.cast(key), indent + "    ",
                    stdout.append(indent).append("DSA").append(System.lineSeparator()));
            return;
        } else if (key instanceof ECPublicKey) {
            dumpECPublicKey(
                    ECPublicKey.class.cast(key), indent + "    ",
                    stdout.append(indent).append("EC").append(System.lineSeparator()));
            return;
        } else if (SecurityUtils.isEDDSACurveSupported()) {
            if (key instanceof EdDSAPublicKey) {
                dumpEdDSAPublicKey(
                        EdDSAPublicKey.class.cast(key), indent + "    ",
                        stdout.append(indent).append("EdDSA").append(System.lineSeparator()));
                return;
            }
        }

        if (stderr != null) {
            stderr.append(indent)
                    .append("Unsupported public key type: ")
                    .append(key.getClass().getName())
                    .append(System.lineSeparator());
        } else {
            throw new UnsupportedOperationException("Unsupported public key type: " + key.getClass().getName());
        }
    }

    public static void dumpPrivateKey(PrivateKey key, CharSequence indent, Appendable stdout, Appendable stderr)
            throws IOException {
        if (key instanceof RSAPrivateKey) {
            dumpRSAPrivateKey(RSAPrivateKey.class.cast(key), indent + "    ",
                    stdout.append(indent).append("RSA").append(System.lineSeparator()));
            return;
        } else if (key instanceof DSAPrivateKey) {
            dumpDSAPrivateKey(DSAPrivateKey.class.cast(key), indent + "    ",
                    stdout.append(indent).append("DSA").append(System.lineSeparator()));
            return;
        } else if (key instanceof ECPrivateKey) {
            dumpECPrivateKey(ECPrivateKey.class.cast(key), indent + "    ",
                    stdout.append(indent).append("EC").append(System.lineSeparator()));
            return;
        } else if (SecurityUtils.isEDDSACurveSupported()) {
            if (key instanceof EdDSAPrivateKey) {
                dumpEdDSAPrivateKey(EdDSAPrivateKey.class.cast(key), indent + "    ",
                        stdout.append(indent).append("EC").append(System.lineSeparator()));
                return;
            }
        }

        if (stderr != null) {
            stderr.append(indent)
                    .append("Unsupported private key type: ")
                    .append(key.getClass().getName())
                    .append(System.lineSeparator());
        } else {
            throw new UnsupportedOperationException("Unsupported private key type: " + key.getClass().getName());
        }
    }

    public static void dumpKey(Key key, CharSequence indent, Appendable stdout, Appendable stderr) throws IOException {
        if (key instanceof PublicKey) {
            dumpPublicKey(PublicKey.class.cast(key), indent, stdout, stderr);
        } else if (key instanceof PrivateKey) {
            dumpPrivateKey(PrivateKey.class.cast(key), indent, stdout, stderr);
        } else if (stderr != null) {
            stderr.append(indent)
                    .append("Unknown key type: ").append(key.getClass().getSimpleName())
                    .append(System.lineSeparator());
        } else {
            throw new ClassCastException("Unknown key type: " + key.getClass().getSimpleName());
        }
    }

    public static void dumpKeyFileData(Path filePath, String password, Appendable stdout, Appendable stderr) throws Exception {
        FilePasswordProvider passwordProvider = GenericUtils.isEmpty(password)
                ? FilePasswordProvider.EMPTY
                : FilePasswordProvider.of(password);
        String fileName = filePath.getFileName().toString();
        Collection<KeyPair> keys;
        if (fileName.endsWith(PuttyKeyPairResourceParser.PPK_FILE_SUFFIX)) {
            keys = PuttyKeyUtils.DEFAULT_INSTANCE.loadKeyPairs(null, filePath, passwordProvider);
        } else if (fileName.endsWith(PublicKeyEntry.PUBKEY_FILE_SUFFIX)
                || AuthorizedKeysAuthenticator.STD_AUTHORIZED_KEYS_FILENAME.equals(fileName)) {
            List<? extends PublicKeyEntry> entries = AuthorizedKeyEntry.readAuthorizedKeys(filePath);
            int numEntries = GenericUtils.size(entries);
            keys = (numEntries <= 0)
                    ? Collections.emptyList()
                    : new ArrayList<>(entries.size());
            for (int index = 0; index < numEntries; index++) {
                PublicKeyEntry e = entries.get(index);
                PublicKey pubKey = e.resolvePublicKey(null, Collections.emptyMap(), null);
                if (pubKey == null) {
                    if (stderr != null) {
                        stderr.append("Cannot resolve public entry=").append(e.toString()).append(System.lineSeparator());
                    } else {
                        throw new UnsupportedOperationException("Cannot resolve public entry=" + e);
                    }
                    continue;
                }

                keys.add(new KeyPair(pubKey, null));
            }
        } else {
            KeyPairResourceLoader loader = SecurityUtils.getKeyPairResourceParser();
            keys = loader.loadKeyPairs(null, filePath, passwordProvider);
        }

        if (GenericUtils.isEmpty(keys)) {
            if (stderr != null) {
                stderr.append("No keys found in ").append(filePath.toString()).append(System.lineSeparator());
                return;
            } else {
                throw new IllegalArgumentException("No keys found in " + filePath);
            }
        }

        for (KeyPair kp : keys) {
            PublicKey pubKey = kp.getPublic();
            PublicKeyEntry.appendPublicKeyEntry(stdout.append("Public key: "), pubKey).append(System.lineSeparator());
            dumpPublicKey(pubKey, "    ", stdout, stderr);

            PrivateKey prvKey = kp.getPrivate();
            if (prvKey != null) {
                stdout.append("Private key:").append(System.lineSeparator());
                dumpPrivateKey(kp.getPrivate(), "    ", stdout, stderr);
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////

    public static void main(String[] args) throws Exception {
        int numArgs = GenericUtils.length(args);
        if (numArgs <= 0) {
            System.err.println("Usage: path [password]");
            return;
        }

        String filePath = PathUtils.normalizePath(args[0]);
        String password = (numArgs > 1) ? args[1] : null;
        dumpKeyFileData(Paths.get(filePath), password, System.out, System.err);
    }
}
