/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.SshConstants;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public final class Buffer {

    public static final int DEFAULT_SIZE = 256;

    private byte[] data;
    private int rpos;
    private int wpos;

    public Buffer() {
        this(DEFAULT_SIZE);
    }

    public Buffer(int size) {
        this(new byte[getNextPowerOf2(size)], false);
    }

    public Buffer(byte[] data) {
        this(data, true);
    }

    public Buffer(byte[] data, boolean read) {
        this.data = data;
        this.rpos = 0;
        this.wpos = read ? data.length : 0;
    }

    @Override
    public String toString() {
        return "Buffer [rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
    }

    /*======================
      Global methods
    ======================*/

    public int rpos() {
        return rpos;
    }

    public void rpos(int rpos) {
        this.rpos = rpos;
    }

    public int wpos() {
        return wpos;
    }

    public void wpos(int wpos) {
        ensureCapacity(wpos - this.wpos);
        this.wpos = wpos;
    }

    public int available() {
        return wpos - rpos;
    }

    public byte[] array() {
        return data;
    }

    public void compact() {
        if (available() > 0) {
            System.arraycopy(data, rpos, data, 0, wpos - rpos);
        }
        wpos -= rpos;
        rpos = 0;
    }

    public byte[] getCompactData() {
        int l = available();
        if (l > 0) {
            byte[] b = new byte[l];
            System.arraycopy(data, rpos, b, 0, l);
            return b;
        } else {
            return new byte[0];
        }
    }

    public void clear() {
        rpos = 0;
        wpos = 0;
    }

    public String printHex() {
        return BufferUtils.printHex(array(), rpos(), available());
    }

    /*======================
       Read methods
     ======================*/

    public byte getByte() {
        ensureAvailable(1);
        return data[rpos++];
    }

    public int getInt() {
        ensureAvailable(4);
        int i = ((data[rpos++] << 24) & 0xff000000)|
                ((data[rpos++] << 16) & 0x00ff0000)|
                ((data[rpos++] <<  8) & 0x0000ff00)|
                ((data[rpos++]      ) & 0x000000ff);
        return i;
    }

    public boolean getBoolean() {
        return getByte() != 0;
    }

    public String getString() {
        int len = getInt();
        if (len < 0 || len > 32768) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        ensureAvailable(len);
        String s = new String(data, rpos, len);
        rpos += len;
        return s;
    }

    public byte[] getStringAsBytes() {
        return getBytes();
    }

    public BigInteger getMPInt() {
        return new BigInteger(getMPIntAsBytes());
    }

    public byte[] getMPIntAsBytes() {
        return getBytes();
    }

    public byte[] getBytes() {
        int len = getInt();
        if (len < 0 || len > 32768) {
            throw new IllegalStateException("Bad item length: " + len);
        }
        byte[] b = new byte[len];
        getRawBytes(b);
        return b;
    }

    public void getRawBytes(byte[] buf) {
        getRawBytes(buf, 0, buf.length);
    }

    public void getRawBytes(byte[] buf, int off, int len) {
        ensureAvailable(len);
        System.arraycopy(data, rpos, buf, off, len);
        rpos += len;
    }

    public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        PublicKey key;
        String keyAlg = getString();
        if (KeyPairProvider.SSH_RSA.equals(keyAlg)) {
            BigInteger e = getMPInt();
            BigInteger n = getMPInt();
            KeyFactory keyFactory = SecurityUtils.getKeyFactory("RSA");
            key = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
        } else if (KeyPairProvider.SSH_DSS.equals(keyAlg)) {
            BigInteger p = getMPInt();
            BigInteger q = getMPInt();
            BigInteger g = getMPInt();
            BigInteger y = getMPInt();
            KeyFactory keyFactory = SecurityUtils.getKeyFactory("DSA");
            key = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
        } else {
            throw new IllegalStateException("Unsupported algorithm: " + keyAlg);
        }
        return key;
    }

    public SshConstants.Message getCommand() {
        byte b = getByte();
        SshConstants.Message cmd = SshConstants.Message.fromByte(b);
        if (cmd == null) {
            throw new IllegalStateException("Unknown command code: " + b);
        }
        return cmd;
    }

    private void ensureAvailable(int a) {
        if (available() < a) {
            throw new BufferException("Underflow");
        }
    }

    /*======================
       Write methods
     ======================*/

    public void putByte(byte b) {
        ensureCapacity(1);
        data[wpos++] = b;
    }

    public void putBuffer(Buffer buffer) {
        int r = buffer.available();
        ensureCapacity(r);
        System.arraycopy(buffer.data, buffer.rpos, data, wpos, r);
        wpos += r;
    }

    public void putBuffer(IoBuffer buffer) {
        int r = buffer.remaining();
        ensureCapacity(r);
        buffer.get(data, wpos, r);
        wpos += r;
    }

    public void putInt(int i) {
        ensureCapacity(4);
        data[wpos++] = (byte) (i >> 24);
        data[wpos++] = (byte) (i >> 16);
        data[wpos++] = (byte) (i >>  8);
        data[wpos++] = (byte) (i      );
    }

    public void putBoolean(boolean b) {
        putByte(b ? (byte) 1 : (byte) 0);
    }

    public void putBytes(byte[] b) {
        putBytes(b, 0, b.length);
    }

    public void putBytes(byte[] b, int off, int len) {
        putInt(len);
        ensureCapacity(len);
        System.arraycopy(b, off, data, wpos, len);
        wpos += len;
    }

    public void putString(String string) {
        putString(string.getBytes());
    }

    public void putString(byte[] str) {
        putInt(str.length);
        putRawBytes(str);
    }

    public void putMPInt(BigInteger bi) {
        putMPInt(bi.toByteArray());
    }

    public void putMPInt(byte[] foo) {
        int i = foo.length;
        if ((foo[0] & 0x80) != 0) {
            i++;
            putInt(i);
            putByte((byte)0);
        } else {
            putInt(i);
        }
        putRawBytes(foo);
    }

    public void putRawBytes(byte[] d) {
        putRawBytes(d, 0, d.length);
    }

    public void putRawBytes(byte[] d, int off, int len) {
        ensureCapacity(len);
        System.arraycopy(d, off, data, wpos, len);
        wpos += len;
    }

    public void putPublicKey(PublicKey key) {
        if (key instanceof RSAPublicKey) {
            putString(KeyPairProvider.SSH_RSA);
            putMPInt(((RSAPublicKey) key).getPublicExponent());
            putMPInt(((RSAPublicKey) key).getModulus());
        } else if (key instanceof DSAPublicKey) {
            putString(KeyPairProvider.SSH_DSS);
            putMPInt(((DSAPublicKey) key).getParams().getP());
            putMPInt(((DSAPublicKey) key).getParams().getQ());
            putMPInt(((DSAPublicKey) key).getParams().getG());
            putMPInt(((DSAPublicKey) key).getY());
        } else {
            throw new IllegalStateException("Unsupported algorithm: " + key.getAlgorithm());
        }
    }

    public void putCommand(SshConstants.Message cmd) {
        putByte(cmd.toByte());
    }

    private void ensureCapacity(int capacity) {
        if (data.length - wpos < capacity) {
            int cw = wpos + capacity;
            byte[] tmp = new byte[getNextPowerOf2(cw)];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
    }

    public static class BufferException extends RuntimeException {
        public BufferException(String message) {
            super(message);
        }
    }

    private static final int getNextPowerOf2(int i) {
        int j = 1;
        while (j < i) {
            j <<= 1;
        }
        return j;
    }

}
