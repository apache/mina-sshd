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
package org.apache.sshd.common.util.buffer;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.function.IntUnaryOperator;
import java.util.logging.Level;

import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.cipher.ECCurves;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.keys.BufferPublicKeyParser;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * Provides an abstract message buffer for encoding SSH messages
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class Buffer implements Readable {
    protected final byte[] workBuf = new byte[Long.BYTES];

    protected Buffer() {
        super();
    }

    public abstract int rpos();

    public abstract void rpos(int rpos);

    public abstract int wpos();

    public abstract void wpos(int wpos);

    public abstract int capacity();

    public abstract byte[] array();

    public abstract void compact();

    public byte[] getCompactData() {
        int l = available();
        if (l > 0) {
            byte[] b = new byte[l];
            System.arraycopy(array(), rpos(), b, 0, l);
            return b;
        } else {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }
    }

    public void clear() {
        clear(true);
    }

    public abstract void clear(boolean wipeData);

    public boolean isValidMessageStructure(Class<?>... fieldTypes) {
        return isValidMessageStructure(GenericUtils.isEmpty(fieldTypes) ? Collections.emptyList() : Arrays.asList(fieldTypes));
    }

    public boolean isValidMessageStructure(Collection<Class<?>> fieldTypes) {
        if (GenericUtils.isEmpty(fieldTypes)) {
            return true;
        }

        int remainLen = available();
        int readOffset = 0;
        for (Class<?> ft : fieldTypes) {
            if ((ft == boolean.class) || (ft == Boolean.class)
                    || (ft == byte.class) || (ft == Byte.class)) {
                if (remainLen < Byte.BYTES) {
                    return false;
                }

                remainLen -= Byte.BYTES;
                readOffset += Byte.BYTES;
            } else if ((ft == short.class) || (ft == Short.class)) {
                if (remainLen < Short.BYTES) {
                    return false;
                }

                remainLen -= Short.BYTES;
                readOffset += Short.BYTES;
            } else if ((ft == int.class) || (ft == Integer.class)) {
                if (remainLen < Integer.BYTES) {
                    return false;
                }

                remainLen -= Integer.BYTES;
                readOffset += Integer.BYTES;
            } else if ((ft == long.class) || (ft == Long.class)) {
                if (remainLen < Long.BYTES) {
                    return false;
                }

                remainLen -= Long.BYTES;
                readOffset += Long.BYTES;
            } else if ((ft == byte[].class) || (ft == String.class)) {
                if (remainLen < Integer.BYTES) {
                    return false;
                }

                copyRawBytes(readOffset, workBuf, 0, Integer.BYTES);
                remainLen -= Integer.BYTES;
                readOffset += Integer.BYTES;

                long length = BufferUtils.getUInt(workBuf, 0, Integer.BYTES);
                if (length > remainLen) {
                    return false;
                }

                remainLen -= (int) length;
                readOffset += (int) length;
            }
        }

        return true;
    }

    protected abstract void copyRawBytes(int offset, byte[] buf, int pos, int len);

    public String toHex() {
        return BufferUtils.toHex(array(), rpos(), available());
    }

    public void dumpHex(SimplifiedLog logger, String prefix, PropertyResolver resolver) {
        dumpHex(logger, BufferUtils.DEFAULT_HEXDUMP_LEVEL, prefix, resolver);
    }

    public void dumpHex(SimplifiedLog logger, Level level, String prefix, PropertyResolver resolver) {
        BufferUtils.dumpHex(logger, level, prefix, resolver, BufferUtils.DEFAULT_HEX_SEPARATOR, array(), rpos(), available());
    }

    /*======================
       Read methods
     ======================*/

    public int getUByte() {
        return getByte() & 0xFF;
    }

    public byte getByte() {
        ensureAvailable(Byte.BYTES);
        getRawBytes(workBuf, 0, Byte.BYTES);
        return workBuf[0];
    }

    public short getShort() {
        ensureAvailable(Short.BYTES);
        getRawBytes(workBuf, 0, Short.BYTES);
        short v = (short) ((workBuf[1] << Byte.SIZE) & 0xFF00);
        v |= (short) (workBuf[0] & 0xF);
        return v;
    }

    public int getInt() {
        return (int) getUInt();
    }

    public long getUInt() {
        ensureAvailable(Integer.BYTES);
        getRawBytes(workBuf, 0, Integer.BYTES);
        return BufferUtils.getUInt(workBuf, 0, Integer.BYTES);
    }

    public long getLong() {
        ensureAvailable(Long.BYTES);
        getRawBytes(workBuf, 0, Long.BYTES);
        long l = ((long) workBuf[0] << 56) & 0xff00000000000000L;
        l |= ((long) workBuf[1] << 48) & 0x00ff000000000000L;
        l |= ((long) workBuf[2] << 40) & 0x0000ff0000000000L;
        l |= ((long) workBuf[3] << 32) & 0x000000ff00000000L;
        l |= ((long) workBuf[4] << 24) & 0x00000000ff000000L;
        l |= ((long) workBuf[5] << 16) & 0x0000000000ff0000L;
        l |= ((long) workBuf[6] << 8) & 0x000000000000ff00L;
        l |= (workBuf[7]) & 0x00000000000000ffL;
        return l;
    }

    @SuppressWarnings("PMD.BooleanGetMethodName")
    public boolean getBoolean() {
        return getByte() != 0;
    }

    public String getString() {
        return getString(StandardCharsets.UTF_8);
    }

    /**
     * @param usePrependedLength If {@code true} then there is a 32-bit
     *                           value indicating the number of strings to read. Otherwise, the
     *                           method will use a &quot;greedy&quot; reading of strings while more
     *                           data available
     * @return A {@link Collection} of the read strings
     * @see #getStringList(boolean, Charset)
     */
    public Collection<String> getStringList(boolean usePrependedLength) {
        return getStringList(usePrependedLength, StandardCharsets.UTF_8);
    }

    /**
     * @param usePrependedLength If {@code true} then there is a 32-bit
     *                           value indicating the number of strings to read. Otherwise, the
     *                           method will use a &quot;greedy&quot; reading of strings while more
     *                           data available
     * @param charset            The {@link Charset} to use for the string
     * @return A {@link Collection} of the read strings
     * @see #getStringList(int, Charset)
     * @see #getAvailableStrings()
     */
    public Collection<String> getStringList(boolean usePrependedLength, Charset charset) {
        if (usePrependedLength) {
            int count = getInt();
            return getStringList(count, charset);
        } else {
            return getAvailableStrings(charset);
        }
    }

    /**
     * @return The remaining data as a list of strings
     * @see #getAvailableStrings(Charset)
     */
    public Collection<String> getAvailableStrings() {
        return getAvailableStrings(StandardCharsets.UTF_8);
    }

    /**
     * @param charset The {@link Charset} to use for the strings
     * @return The remaining data as a list of strings
     * @see #available()
     * @see #getString(Charset)
     */
    public Collection<String> getAvailableStrings(Charset charset) {
        Collection<String> list = new LinkedList<>();
        while (available() > 0) {
            String s = getString(charset);
            list.add(s);
        }

        return list;
    }

    /**
     * @param count The <U>exact</U> number of strings to read - can be zero
     * @return A {@link List} with the specified number of strings
     * @see #getStringList(int, Charset)
     */
    public List<String> getStringList(int count) {
        return getStringList(count, StandardCharsets.UTF_8);
    }

    /**
     * @param count   The <U>exact</U> number of strings to read - can be zero
     * @param charset The {@link Charset} of the strings
     * @return A {@link List} with the specified number of strings
     * @see #getString(Charset)
     */
    public List<String> getStringList(int count, Charset charset) {
        if (count == 0) {
            return Collections.emptyList();
        }

        List<String> list = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            String s = getString(charset);
            list.add(s);
        }

        return list;
    }

    public abstract String getString(Charset charset);

    public BigInteger getMPInt() {
        return new BigInteger(getMPIntAsBytes());
    }

    public byte[] getMPIntAsBytes() {
        return getBytes();
    }

    public byte[] getBytes() {
        int len = getInt();
        if (len < 0) {
            throw new BufferException("Bad item length: " + len);
        }
        ensureAvailable(len);
        byte[] b = new byte[len];
        getRawBytes(b);
        return b;
    }

    public void getRawBytes(byte[] buf) {
        getRawBytes(buf, 0, buf.length);
    }

    public PublicKey getPublicKey() throws SshException {
        return getPublicKey(BufferPublicKeyParser.DEFAULT);
    }

    /**
     * @param parser A {@link BufferPublicKeyParser} to extract the key from the buffer
     * - never {@code null}
     * @return The extracted {@link PublicKey} - may be {@code null} if the parser so decided
     * @throws SshException If failed to extract the key
     * @see #getRawPublicKey(BufferPublicKeyParser)
     */
    public PublicKey getPublicKey(BufferPublicKeyParser<? extends PublicKey> parser) throws SshException {
        int ow = wpos();
        int len = getInt();
        wpos(rpos() + len);
        try {
            return getRawPublicKey(parser);
        } finally {
            wpos(ow);
        }
    }

    public PublicKey getRawPublicKey() throws SshException {
        return getRawPublicKey(BufferPublicKeyParser.DEFAULT);
    }

    /**
     * @param parser A {@link BufferPublicKeyParser} to extract the key from the buffer
     * - never {@code null}
     * @return The extracted {@link PublicKey} - may be {@code null} if the parser so decided
     * @throws SshException If failed to extract the key
     */
    public PublicKey getRawPublicKey(BufferPublicKeyParser<? extends PublicKey> parser) throws SshException {
        Objects.requireNonNull(parser, "No key data parser");
        try {
            String keyType = getString();
            if (!parser.isKeyTypeSupported(keyType)) {
                throw new NoSuchAlgorithmException("Key type=" + keyType + ") not supported by parser=" + parser);
            }

            return parser.getRawPublicKey(keyType, this);
        } catch (GeneralSecurityException e) {
            throw new SshException(e);
        }
    }

    public KeyPair getKeyPair() throws SshException {
        try {
            final PublicKey pub;
            final PrivateKey prv;
            final String keyAlg = getString();
            if (KeyPairProvider.SSH_RSA.equals(keyAlg)) {
                BigInteger e = getMPInt();
                BigInteger n = getMPInt();
                BigInteger d = getMPInt();
                BigInteger qInv = getMPInt();
                BigInteger q = getMPInt();
                BigInteger p = getMPInt();
                BigInteger dP = d.remainder(p.subtract(BigInteger.valueOf(1)));
                BigInteger dQ = d.remainder(q.subtract(BigInteger.valueOf(1)));
                KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyUtils.RSA_ALGORITHM);
                pub = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
                prv = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(n, e, d, p, q, dP, dQ, qInv));
            } else if (KeyPairProvider.SSH_DSS.equals(keyAlg)) {
                BigInteger p = getMPInt();
                BigInteger q = getMPInt();
                BigInteger g = getMPInt();
                BigInteger y = getMPInt();
                BigInteger x = getMPInt();
                KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyUtils.DSS_ALGORITHM);
                pub = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
                prv = keyFactory.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
            } else if (KeyPairProvider.SSH_ED25519.equals(keyAlg)) {
                return SecurityUtils.extractEDDSAKeyPair(this, keyAlg);
            } else {
                ECCurves curve = ECCurves.fromKeyType(keyAlg);
                if (curve == null) {
                    throw new NoSuchAlgorithmException("Unsupported key pair algorithm: " + keyAlg);
                }
                String curveName = curve.getName();
                ECParameterSpec params = curve.getParameters();
                return extractEC(curveName, params);
            }

            return new KeyPair(pub, prv);
        } catch (GeneralSecurityException e) {
            throw new SshException(e);
        }
    }

    protected KeyPair extractEC(String expectedCurveName, ECParameterSpec spec) throws GeneralSecurityException {
        String curveName = getString();
        if (!expectedCurveName.equals(curveName)) {
            throw new InvalidKeySpecException("extractEC(" + expectedCurveName + ") mismatched curve name: " + curveName);
        }

        byte[] groupBytes = getBytes();
        BigInteger exponent = getMPInt();

        if (spec == null) {
            throw new InvalidKeySpecException("extractEC(" + expectedCurveName + ") missing parameters for curve");
        }

        ECPoint group;
        try {
            group = ECCurves.octetStringToEcPoint(groupBytes);
        } catch (RuntimeException e) {
            throw new InvalidKeySpecException("extractEC(" + expectedCurveName + ")"
                    + " failed (" + e.getClass().getSimpleName() + ")"
                    + " to decode EC group for curve: " + e.getMessage(),
                    e);
        }

        KeyFactory keyFactory = SecurityUtils.getKeyFactory(KeyUtils.EC_ALGORITHM);
        PublicKey pubKey = keyFactory.generatePublic(new ECPublicKeySpec(group, spec));
        PrivateKey privKey = keyFactory.generatePrivate(new ECPrivateKeySpec(exponent, spec));
        return new KeyPair(pubKey, privKey);
    }

    public void ensureAvailable(int reqLen) throws BufferException {
        int availLen = available();
        if (availLen < reqLen) {
            throw new BufferException("Underflow: requested=" + reqLen + ", available=" + availLen);
        }
    }

    /*======================
       Write methods
     ======================*/

    public void putByte(byte b) {
        ensureCapacity(Byte.BYTES);
        workBuf[0] = b;
        putRawBytes(workBuf, 0, Byte.BYTES);
    }

    public void putBuffer(Readable buffer) {
        putBuffer(buffer, true);
    }

    public abstract int putBuffer(Readable buffer, boolean expand);

    public abstract void putBuffer(ByteBuffer buffer);

    /**
     * Writes 16 bits
     *
     * @param i The 16-bit value
     */
    public void putShort(int i) {
        ensureCapacity(Short.BYTES);
        workBuf[0] = (byte) (i >> 8);
        workBuf[1] = (byte) i;
        putRawBytes(workBuf, 0, Short.BYTES);
    }

    /**
     * Writes 32 bits
     *
     * @param i The 32-bit value
     */
    public void putInt(long i) {
        BufferUtils.validateInt32Value(i, "Invalid 32-bit value: %d");
        ensureCapacity(Integer.BYTES);
        BufferUtils.putUInt(i, workBuf, 0, Integer.BYTES);
        putRawBytes(workBuf, 0, Integer.BYTES);
    }

    /**
     * Writes 64 bits
     *
     * @param i The 64-bit value
     */
    public void putLong(long i) {
        ensureCapacity(Long.BYTES);
        workBuf[0] = (byte) (i >> 56);
        workBuf[1] = (byte) (i >> 48);
        workBuf[2] = (byte) (i >> 40);
        workBuf[3] = (byte) (i >> 32);
        workBuf[4] = (byte) (i >> 24);
        workBuf[5] = (byte) (i >> 16);
        workBuf[6] = (byte) (i >> 8);
        workBuf[7] = (byte) i;
        putRawBytes(workBuf, 0, Long.BYTES);
    }

    public void putBoolean(boolean b) {
        putByte(b ? (byte) 1 : (byte) 0);
    }

    /**
     * Adds the bytes to the buffer and wipes the data from the
     * input buffer <U>after</U> having added it - useful for sensitive
     * information such as password
     *
     * @param b The buffer to add - OK if {@code null}
     */
    public void putAndWipeBytes(byte[] b) {
        putAndWipeBytes(b, 0, NumberUtils.length(b));
    }

    public void putAndWipeBytes(byte[] b, int off, int len) {
        putBytes(b, off, len);

        for (int pos = off, index = 0; index < len; pos++, index++) {
            b[pos] = (byte) 0;
        }
    }

    public void putBytes(byte[] b) {
        putBytes(b, 0, NumberUtils.length(b));
    }

    public void putBytes(byte[] b, int off, int len) {
        putInt(len);
        putRawBytes(b, off, len);
    }

    /**
     * Encodes the {@link Objects#toString(Object, String) toString} value of each member.
     *
     * @param objects       The objects to be encoded in the buffer - OK if
     *                      {@code null}/empty
     * @param prependLength If {@code true} then the list is preceded by
     *                      a 32-bit count of the number of members in the list
     * @see #putStringList(Collection, Charset, boolean)
     */
    public void putStringList(Collection<?> objects, boolean prependLength) {
        putStringList(objects, StandardCharsets.UTF_8, prependLength);
    }

    /**
     * Encodes the {@link Objects#toString(Object, String) toString} value of each member
     *
     * @param objects       The objects to be encoded in the buffer - OK if
     *                      {@code null}/empty
     * @param charset       The {@link Charset} to use for encoding
     * @param prependLength If {@code true} then the list is preceded by
     *                      a 32-bit count of the number of members in the list
     * @see #putString(String, Charset)
     */
    public void putStringList(Collection<?> objects, Charset charset, boolean prependLength) {
        int numObjects = GenericUtils.size(objects);
        if (prependLength) {
            putInt(numObjects);
        }

        if (numObjects <= 0) {
            return;
        }

        objects.forEach(o -> putString(Objects.toString(o, null), charset));
    }

    public void putString(String string) {
        putString(string, StandardCharsets.UTF_8);
    }

    public void putString(String string, Charset charset) {
        if (GenericUtils.isEmpty(string)) {
            putBytes(GenericUtils.EMPTY_BYTE_ARRAY);
        } else {
            putBytes(string.getBytes(charset));
        }
    }

    /**
     * Zeroes the input array <U>after</U> having put the characters in the
     * buffer - useful for sensitive information such as passwords
     *
     * @param chars The characters to put in the buffer - may be {@code null}/empty
     * @see #putAndWipeChars(char[], Charset)
     * @see #putChars(char[], Charset)
     */
    public void putAndWipeChars(char[] chars) {
        putAndWipeChars(chars, 0, GenericUtils.length(chars));
    }

    public void putAndWipeChars(char[] chars, int offset, int len) {
        putAndWipeChars(chars, offset, len, StandardCharsets.UTF_8);
    }

    public void putAndWipeChars(char[] chars, Charset charset) {
        putAndWipeChars(chars, 0, GenericUtils.length(chars), charset);
    }

    public void putAndWipeChars(char[] chars, int offset, int len, Charset charset) {
        putChars(chars, offset, len, charset);
        for (int pos = offset, index = 0; index < len; index++, pos++) {
            chars[pos] = '\0';
        }
    }

    public void putChars(char[] chars) {
        putChars(chars, 0, GenericUtils.length(chars));
    }

    public void putChars(char[] chars, int offset, int len) {
        putChars(chars, offset, len, StandardCharsets.UTF_8);
    }

    public void putChars(char[] chars, Charset charset) {
        putChars(chars, 0, GenericUtils.length(chars), charset);
    }

    public void putChars(char[] chars, int offset, int len, Charset charset) {
        if (len <= 0) {
            putBytes(GenericUtils.EMPTY_BYTE_ARRAY);
        } else {
            putBuffer(charset.encode(CharBuffer.wrap(chars, offset, len)));
        }
    }

    public void putMPInt(BigInteger bi) {
        putMPInt(bi.toByteArray());
    }

    public void putMPInt(byte[] foo) {
        if ((foo[0] & 0x80) != 0) {
            putInt(foo.length + 1 /* padding */);
            putByte((byte) 0);
        } else {
            putInt(foo.length);
        }
        putRawBytes(foo);
    }

    public void putRawBytes(byte[] d) {
        putRawBytes(d, 0, d.length);
    }

    public abstract void putRawBytes(byte[] d, int off, int len);

    public void putPublicKey(PublicKey key) {
        int ow = wpos();
        putInt(0);
        int ow1 = wpos();
        putRawPublicKey(key);
        int ow2 = wpos();
        wpos(ow);
        putInt(ow2 - ow1);
        wpos(ow2);
    }

    public void putRawPublicKey(PublicKey key) {
        Objects.requireNonNull(key, "No key");
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaPub = (RSAPublicKey) key;

            putString(KeyPairProvider.SSH_RSA);
            putMPInt(rsaPub.getPublicExponent());
            putMPInt(rsaPub.getModulus());
        } else if (key instanceof DSAPublicKey) {
            DSAPublicKey dsaPub = (DSAPublicKey) key;
            DSAParams dsaParams = dsaPub.getParams();

            putString(KeyPairProvider.SSH_DSS);
            putMPInt(dsaParams.getP());
            putMPInt(dsaParams.getQ());
            putMPInt(dsaParams.getG());
            putMPInt(dsaPub.getY());
        } else if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey) key;
            ECParameterSpec ecParams = ecKey.getParams();
            ECCurves curve = ECCurves.fromCurveParameters(ecParams);
            if (curve == null) {
                throw new BufferException("Unsupported EC curve parameters");
            }

            putString(curve.getKeyType());
            putString(curve.getName());
            putBytes(ECCurves.encodeECPoint(ecKey.getW(), ecParams));
        } else if (SecurityUtils.EDDSA.equals(key.getAlgorithm())) {
            SecurityUtils.putRawEDDSAPublicKey(this, key);
        } else {
            throw new BufferException("Unsupported raw public key algorithm: " + key.getAlgorithm());
        }
    }

    public void putKeyPair(KeyPair kp) {
        PublicKey pubKey = kp.getPublic();
        PrivateKey prvKey = kp.getPrivate();
        if (prvKey instanceof RSAPrivateCrtKey) {
            RSAPublicKey rsaPub = (RSAPublicKey) pubKey;
            RSAPrivateCrtKey rsaPrv = (RSAPrivateCrtKey) prvKey;

            putString(KeyPairProvider.SSH_RSA);
            putMPInt(rsaPub.getPublicExponent());
            putMPInt(rsaPub.getModulus());
            putMPInt(rsaPrv.getPrivateExponent());
            putMPInt(rsaPrv.getCrtCoefficient());
            putMPInt(rsaPrv.getPrimeQ());
            putMPInt(rsaPrv.getPrimeP());
        } else if (pubKey instanceof DSAPublicKey) {
            DSAPublicKey dsaPub = (DSAPublicKey) pubKey;
            DSAParams dsaParams = dsaPub.getParams();
            DSAPrivateKey dsaPrv = (DSAPrivateKey) prvKey;

            putString(KeyPairProvider.SSH_DSS);
            putMPInt(dsaParams.getP());
            putMPInt(dsaParams.getQ());
            putMPInt(dsaParams.getG());
            putMPInt(dsaPub.getY());
            putMPInt(dsaPrv.getX());
        } else if (pubKey instanceof ECPublicKey) {
            ECPublicKey ecPub = (ECPublicKey) pubKey;
            ECPrivateKey ecPriv = (ECPrivateKey) prvKey;
            ECParameterSpec ecParams = ecPub.getParams();
            ECCurves curve = ECCurves.fromCurveParameters(ecParams);
            if (curve == null) {
                throw new BufferException("Unsupported EC curve parameters");
            }

            putString(curve.getKeyType());
            putString(curve.getName());
            putBytes(ECCurves.encodeECPoint(ecPub.getW(), ecParams));
            putMPInt(ecPriv.getS());
        } else if (SecurityUtils.EDDSA.equals(pubKey.getAlgorithm())) {
            SecurityUtils.putEDDSAKeyPair(this, pubKey, prvKey);
        } else {
            throw new BufferException("Unsupported key pair algorithm: " + pubKey.getAlgorithm());
        }
    }

    protected void ensureCapacity(int capacity) {
        ensureCapacity(capacity, BufferUtils.DEFAULT_BUFFER_GROWTH_FACTOR);
    }

    /**
     * @param capacity     The requires capacity
     * @param growthFactor An {@link IntUnaryOperator} that is invoked
     *                     if the current capacity is insufficient. The argument is the minimum
     *                     required new data length, the function result should be the
     *                     effective new data length to be allocated - if less than minimum
     *                     then an exception is thrown
     */
    public abstract void ensureCapacity(int capacity, IntUnaryOperator growthFactor);

    protected abstract int size();

    @Override
    public String toString() {
        return "Buffer [rpos=" + rpos() + ", wpos=" + wpos() + ", size=" + size() + "]";
    }
}
