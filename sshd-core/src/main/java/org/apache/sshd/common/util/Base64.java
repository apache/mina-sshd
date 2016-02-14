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
package org.apache.sshd.common.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;

/**
 * <p>Provides Base64 encoding and decoding as defined by RFC 2045.</p>
 *
 * <p>This class implements section <cite>6.8. Base64 Content-Transfer-Encoding</cite>
 * from RFC 2045 <cite>Multipurpose Internet Mail Extensions (MIME) Part One:
 * Format of Internet Message Bodies</cite> by Freed and Borenstein.</p>
 *
 * @author Apache Software Foundation commons codec (http://commons.apache.org/codec/)
 * @author <a href="http://mina.apache.org">Apache MINA Project</a>
 *         TODO replace this class with {@code java.util.Base64} when upgrading to JDK 1.8
 * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045</a>
 */
public final class Base64 {

    /**
     * <P>Chunk size per RFC 2045 section 6.8.</P>
     *
     * <p>The {@value} character limit does not count the trailing CRLF, but counts
     * all other characters, including any equal signs.</p>
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 6.8</a>
     */
    public static final int CHUNK_SIZE = 76;

    /**
     * The base length.
     */
    public static final int BASELENGTH = 255;

    /**
     * Lookup length.
     */
    public static final int LOOKUPLENGTH = 64;

    /**
     * Used to calculate the number of bits in a byte.
     */
    public static final int EIGHTBIT = Byte.SIZE;

    /**
     * Used when encoding something which has fewer than 24 bits.
     */
    public static final int SIXTEENBIT = 2 * EIGHTBIT;

    /**
     * Used to determine how many bits data contains.
     */
    public static final int TWENTYFOURBITGROUP = 3 * EIGHTBIT;

    /**
     * Used to get the number of Quadruples.
     */
    public static final int FOURBYTE = 4;

    /**
     * Used to test the sign of a byte.
     */
    public static final int SIGN = -128;

    /**
     * Byte used to pad output.
     */
    public static final byte PAD = (byte) '=';

    /**
     * Chunk separator per RFC 2045 section 2.1.
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 2.1</a>
     */
    static final byte[] CHUNK_SEPARATOR = "\r\n".getBytes(StandardCharsets.UTF_8);

    // Create arrays to hold the base64 characters and a
    // lookup for base64 chars
    private static byte[] base64Alphabet = new byte[BASELENGTH];

    private static byte[] lookUpBase64Alphabet = new byte[LOOKUPLENGTH];

    // Populating the lookup and character arrays
    static {
        for (int i = 0; i < BASELENGTH; i++) {
            base64Alphabet[i] = (byte) -1;
        }
        for (int i = 'Z'; i >= 'A'; i--) {
            base64Alphabet[i] = (byte) (i - 'A');
        }
        for (int i = 'z'; i >= 'a'; i--) {
            base64Alphabet[i] = (byte) (i - 'a' + 26);
        }
        for (int i = '9'; i >= '0'; i--) {
            base64Alphabet[i] = (byte) (i - '0' + 52);
        }

        base64Alphabet['+'] = 62;
        base64Alphabet['/'] = 63;

        for (int i = 0; i <= 25; i++) {
            lookUpBase64Alphabet[i] = (byte) ('A' + i);
        }

        for (int i = 26, j = 0; i <= 51; i++, j++) {
            lookUpBase64Alphabet[i] = (byte) ('a' + j);
        }

        for (int i = 52, j = 0; i <= 61; i++, j++) {
            lookUpBase64Alphabet[i] = (byte) ('0' + j);
        }

        lookUpBase64Alphabet[62] = (byte) '+';
        lookUpBase64Alphabet[63] = (byte) '/';
    }

    private Base64() {
        throw new UnsupportedOperationException("No instance");
    }

    public static boolean isBase64(byte octect) {
        return octect == PAD || base64Alphabet[octect] != -1;
    }

    /**
     * Tests a given byte array to see if it contains
     * only valid characters within the Base64 alphabet.
     *
     * @param arrayOctect byte array to test
     * @return true if all bytes are valid characters in the Base64
     * alphabet or if the byte array is empty; false, otherwise
     */
    public static boolean isArrayByteBase64(byte[] arrayOctect) {
        arrayOctect = discardWhitespace(arrayOctect);

        int length = NumberUtils.length(arrayOctect);
        if (length == 0) {
            // shouldn't a 0 length array be valid base64 data?
            return true;
        }
        for (byte anArrayOctect : arrayOctect) {
            if (!isBase64(anArrayOctect)) {
                return false;
            }
        }
        return true;
    }

    public static String encodeToString(byte... bytes) {
        return new String(encodeBase64(bytes), StandardCharsets.UTF_8);
    }

    /**
     * Encodes binary data using the base64 algorithm but
     * does not chunk the output.
     *
     * @param binaryData binary data to encode
     * @return Base64 characters
     */
    public static byte[] encodeBase64(byte[] binaryData) {
        return encodeBase64(binaryData, false);
    }

    /**
     * Encodes binary data using the base64 algorithm and chunks
     * the encoded output into 76 character blocks
     *
     * @param binaryData binary data to encode
     * @return Base64 characters chunked in 76 character blocks
     */
    public static byte[] encodeBase64Chunked(byte[] binaryData) {
        return encodeBase64(binaryData, true);
    }

    /**
     * Decodes an Object using the base64 algorithm.  This method
     * is provided in order to satisfy the requirements of the
     * Decoder interface, and will throw a DecoderException if the
     * supplied object is not of type byte[].
     *
     * @param pObject Object to decode
     * @return An object (of type byte[]) containing the
     * binary data which corresponds to the byte[] supplied.
     * @throws InvalidParameterException if the parameter supplied is not
     *                                   of type byte[]
     */
    public Object decode(Object pObject) {
        if (!(pObject instanceof byte[])) {
            throw new InvalidParameterException("Parameter supplied to Base64 decode is not a byte[]");
        }
        return decode((byte[]) pObject);
    }

    /**
     * Decodes a byte[] containing containing
     * characters in the Base64 alphabet.
     *
     * @param pArray A byte array containing Base64 character data
     * @return a byte array containing binary data
     */
    public byte[] decode(byte[] pArray) {
        return decodeBase64(pArray);
    }

    /**
     * Encodes binary data using the base64 algorithm, optionally
     * chunking the output into 76 character blocks.
     *
     * @param binaryData Array containing binary data to encode.
     * @param isChunked  if isChunked is true this encoder will chunk
     *                   the base64 output into 76 character blocks
     * @return Base64-encoded data.
     */
    public static byte[] encodeBase64(byte[] binaryData, boolean isChunked) {
        int lengthDataBytes = NumberUtils.length(binaryData);
        int lengthDataBits = lengthDataBytes * EIGHTBIT;
        int fewerThan24bits = lengthDataBits % TWENTYFOURBITGROUP;
        int numberTriplets = lengthDataBits / TWENTYFOURBITGROUP;
        byte encodedData[];
        int encodedDataLength;
        int nbrChunks = 0;

        if (fewerThan24bits != 0) {
            //data not divisible by 24 bit
            encodedDataLength = (numberTriplets + 1) * 4;
        } else {
            // 16 or 8 bit
            encodedDataLength = numberTriplets * 4;
        }

        // If the output is to be "chunked" into 76 character sections,
        // for compliance with RFC 2045 MIME, then it is important to
        // allow for extra length to account for the separator(s)
        if (isChunked) {
            nbrChunks = CHUNK_SEPARATOR.length == 0 ? 0 : (int) Math.ceil((float) encodedDataLength / CHUNK_SIZE);
            encodedDataLength += nbrChunks * CHUNK_SEPARATOR.length;
        }

        encodedData = new byte[encodedDataLength];

        byte k;
        byte l;
        byte b1;
        byte b2;
        byte b3;

        int encodedIndex = 0;
        int dataIndex;
        int i;
        int nextSeparatorIndex = CHUNK_SIZE;
        int chunksSoFar = 0;

        for (i = 0; i < numberTriplets; i++) {
            dataIndex = i * 3;
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            b3 = binaryData[dataIndex + 2];

            l = (byte) (b2 & 0x0f);
            k = (byte) (b1 & 0x03);

            byte val1 = (b1 & SIGN) == 0 ? (byte) (b1 >> 2) : (byte) (b1 >> 2 ^ 0xc0);
            byte val2 = (b2 & SIGN) == 0 ? (byte) (b2 >> 4) : (byte) (b2 >> 4 ^ 0xf0);
            byte val3 = (b3 & SIGN) == 0 ? (byte) (b3 >> 6) : (byte) (b3 >> 6 ^ 0xfc);

            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = lookUpBase64Alphabet[(l << 2) | val3];
            encodedData[encodedIndex + 3] = lookUpBase64Alphabet[b3 & 0x3f];

            encodedIndex += 4;

            // If we are chunking, let's put a chunk separator down.
            if (isChunked) {
                // this assumes that CHUNK_SIZE % 4 == 0
                if (encodedIndex == nextSeparatorIndex) {
                    System.arraycopy(CHUNK_SEPARATOR, 0, encodedData, encodedIndex, CHUNK_SEPARATOR.length);
                    chunksSoFar++;
                    nextSeparatorIndex = (CHUNK_SIZE * (chunksSoFar + 1)) + (chunksSoFar * CHUNK_SEPARATOR.length);
                    encodedIndex += CHUNK_SEPARATOR.length;
                }
            }
        }

        // form integral number of 6-bit groups
        dataIndex = i * 3;

        if (fewerThan24bits == EIGHTBIT) {
            b1 = binaryData[dataIndex];
            k = (byte) (b1 & 0x03);
            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) (b1 >> 2 ^ 0xc0);
            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[k << 4];
            encodedData[encodedIndex + 2] = PAD;
            encodedData[encodedIndex + 3] = PAD;
        } else if (fewerThan24bits == SIXTEENBIT) {
            b1 = binaryData[dataIndex];
            b2 = binaryData[dataIndex + 1];
            l = (byte) (b2 & 0x0f);
            k = (byte) (b1 & 0x03);

            byte val1 = ((b1 & SIGN) == 0) ? (byte) (b1 >> 2) : (byte) (b1 >> 2 ^ 0xc0);
            byte val2 = ((b2 & SIGN) == 0) ? (byte) (b2 >> 4) : (byte) (b2 >> 4 ^ 0xf0);

            encodedData[encodedIndex] = lookUpBase64Alphabet[val1];
            encodedData[encodedIndex + 1] = lookUpBase64Alphabet[val2 | (k << 4)];
            encodedData[encodedIndex + 2] = lookUpBase64Alphabet[l << 2];
            encodedData[encodedIndex + 3] = PAD;
        }

        if (isChunked) {
            // we also add a separator to the end of the final chunk.
            if (chunksSoFar < nbrChunks) {
                System.arraycopy(CHUNK_SEPARATOR, 0, encodedData, encodedDataLength - CHUNK_SEPARATOR.length,
                        CHUNK_SEPARATOR.length);
            }
        }

        return encodedData;
    }

    public static byte[] decodeString(String s) {
        if (GenericUtils.isEmpty(s)) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        } else {
            return decodeBase64(s.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Decodes Base64 data into octects
     *
     * @param base64Data Byte array containing Base64 data
     * @return Array containing decoded data.
     */
    public static byte[] decodeBase64(byte[] base64Data) {
        // RFC 2045 requires that we discard ALL non-Base64 characters
        base64Data = discardNonBase64(base64Data);

        // handle the edge case, so we don't have to worry about it later
        if (NumberUtils.isEmpty(base64Data)) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        int numberQuadruple = base64Data.length / FOURBYTE;
        byte decodedData[];
        byte b1;
        byte b2;
        byte b3;
        byte b4;
        byte marker0;
        byte marker1;

        // Throw away anything not in base64Data

        int encodedIndex = 0;
        int dataIndex;

        // this sizes the output array properly - rlw
        int lastData = base64Data.length;
        // ignore the '=' padding
        while (base64Data[lastData - 1] == PAD) {
            if (--lastData == 0) {
                return GenericUtils.EMPTY_BYTE_ARRAY;
            }
        }
        decodedData = new byte[lastData - numberQuadruple];

        for (int i = 0; i < numberQuadruple; i++) {
            dataIndex = i * 4;
            marker0 = base64Data[dataIndex + 2];
            marker1 = base64Data[dataIndex + 3];

            b1 = base64Alphabet[base64Data[dataIndex]];
            b2 = base64Alphabet[base64Data[dataIndex + 1]];

            if (marker0 != PAD && marker1 != PAD) {
                //No PAD e.g 3cQl
                b3 = base64Alphabet[marker0];
                b4 = base64Alphabet[marker1];

                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
                decodedData[encodedIndex + 2] = (byte) (b3 << 6 | b4);
            } else if (marker0 == PAD) {
                //Two PAD e.g. 3c[Pad][Pad]
                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
            } else if (marker1 == PAD) {
                //One PAD e.g. 3cQ[Pad]
                b3 = base64Alphabet[marker0];

                decodedData[encodedIndex] = (byte) (b1 << 2 | b2 >> 4);
                decodedData[encodedIndex + 1] = (byte) (((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf));
            }
            encodedIndex += 3;
        }
        return decodedData;
    }

    /**
     * Discards any whitespace from a base-64 encoded block.
     *
     * @param data The base-64 encoded data to discard the whitespace
     *             from.
     * @return The data, less whitespace (see RFC 2045) - may be same
     * as input if no whitespace found
     */
    public static byte[] discardWhitespace(byte[] data) {
        if (NumberUtils.isEmpty(data)) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        byte groomedData[] = null;
        int bytesCopied = 0;

        for (int index = 0; index < data.length; index++) {
            byte v = data[index];
            boolean isWhiteSpace = (v == (byte) ' ') || (v == (byte) '\t') || (v == (byte) '\r') || (v == (byte) '\n');
            if (groomedData == null) {
                if (isWhiteSpace) { // all values up to this index were NOT white space
                    groomedData = new byte[data.length - 1];
                    if (index > 0) {
                        System.arraycopy(data, 0, groomedData, 0, index);
                    }
                    bytesCopied = index;
                }
            } else {
                if (isWhiteSpace) {
                    continue;
                }
                groomedData[bytesCopied++] = v;
            }
        }

        if (groomedData == null) {
            return data;    // all characters where non-whitespace
        }

        if (bytesCopied <= 0) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        if (bytesCopied == groomedData.length) {
            return groomedData;
        }

        byte[] packedData = new byte[bytesCopied];
        System.arraycopy(groomedData, 0, packedData, 0, bytesCopied);
        return packedData;
    }

    /**
     * Discards any characters outside of the base64 alphabet, per
     * the requirements on page 25 of RFC 2045 - "Any characters
     * outside of the base64 alphabet are to be ignored in base64
     * encoded data."
     *
     * @param data The base-64 encoded data to groom
     * @return The data, less non-base64 characters (see RFC 2045) -
     * may be same as input if all data was base-64
     */
    public static byte[] discardNonBase64(byte[] data) {
        if (NumberUtils.isEmpty(data)) {
            return data;
        }

        byte groomedData[] = null;
        int bytesCopied = 0;

        for (int i = 0; i < data.length; i++) {
            byte b = data[i];

            if (isBase64(b)) {
                if (groomedData != null) {
                    // we had to filter out some non-BASE64 bytes
                    groomedData[bytesCopied++] = b;
                }
            } else {
                // this means ALL the characters up to this index were BASE64
                if (groomedData == null) {
                    groomedData = new byte[data.length - 1 /* the current character, which is NOT BASE64 */];

                    bytesCopied = i;
                    if (bytesCopied > 0) {
                        System.arraycopy(data, 0, groomedData, 0, bytesCopied);
                    }
                }
            }
        }

        if (groomedData == null) {
            return data;    // all characters where BASE64
        }

        if (bytesCopied <= 0) {
            return GenericUtils.EMPTY_BYTE_ARRAY;
        }

        // if we were lucky and only ONE character was groomed
        if (bytesCopied == groomedData.length) {
            return groomedData;
        }

        byte packedData[] = new byte[bytesCopied];
        System.arraycopy(groomedData, 0, packedData, 0, bytesCopied);
        return packedData;
    }

    // Implementation of the Encoder Interface

    /**
     * Encodes an Object using the base64 algorithm.  This method
     * is provided in order to satisfy the requirements of the
     * Encoder interface, and will throw an EncoderException if the
     * supplied object is not of type byte[].
     *
     * @param pObject Object to encode
     * @return An object (of type byte[]) containing the
     * base64 encoded data which corresponds to the byte[] supplied.
     * @throws InvalidParameterException if the parameter supplied is not
     *                                   of type byte[]
     */
    public Object encode(Object pObject) {
        if (!(pObject instanceof byte[])) {
            throw new InvalidParameterException("Parameter supplied to Base64 encode is not a byte[]");
        }
        return encode((byte[]) pObject);
    }

    /**
     * Encodes a byte[] containing binary data, into a byte[] containing
     * characters in the Base64 alphabet.
     *
     * @param pArray a byte array containing binary data
     * @return A byte array containing only Base64 character data
     */
    public byte[] encode(byte[] pArray) {
        return encodeBase64(pArray, false);
    }

}