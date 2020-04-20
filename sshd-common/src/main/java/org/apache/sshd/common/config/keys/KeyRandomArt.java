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

package org.apache.sshd.common.config.keys;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.AlgorithmNameProvider;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.digest.Digest;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeySizeIndicator;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Draw an ASCII-Art representing the fingerprint so human brain can profit from its built-in pattern recognition
 * ability. This technique is called "random art" and can be found in some scientific publications like this original
 * paper:
 *
 * &quot;Hash Visualization: a New Technique to improve Real-World Security&quot;, Perrig A. and Song D., 1999,
 * International Workshop on Cryptographic Techniques and E-Commerce (CrypTEC '99)
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <a href="http://sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf">Original article</a>
 * @see    <a href="http://opensource.apple.com/source/OpenSSH/OpenSSH-175/openssh/key.c">C implementation</a>
 */
public class KeyRandomArt implements AlgorithmNameProvider, KeySizeIndicator {
    public static final int FLDBASE = 8;
    public static final int FLDSIZE_Y = FLDBASE + 1;
    public static final int FLDSIZE_X = FLDBASE * 2 + 1;
    public static final String AUGMENTATION_STRING = " .o+=*BOX@%&#/^SE";

    private final String algorithm;
    private final int keySize;
    private final char[][] field = new char[FLDSIZE_X][FLDSIZE_Y];

    public KeyRandomArt(PublicKey key) throws Exception {
        this(key, KeyUtils.getDefaultFingerPrintFactory());
    }

    public KeyRandomArt(PublicKey key, Factory<? extends Digest> f) throws Exception {
        this(key, Objects.requireNonNull(f, "No digest factory").create());
    }

    public KeyRandomArt(PublicKey key, Digest d) throws Exception {
        this(Objects.requireNonNull(key, "No key provided").getAlgorithm(),
             KeyUtils.getKeySize(key),
             KeyUtils.getRawFingerprint(Objects.requireNonNull(d, "No key digest"), key));
    }

    /**
     * @param algorithm The key algorithm
     * @param keySize   The key size in bits
     * @param digest    The key digest
     */
    public KeyRandomArt(String algorithm, int keySize, byte[] digest) {
        this.algorithm = ValidateUtils.checkNotNullAndNotEmpty(algorithm, "No algorithm provided");
        ValidateUtils.checkTrue(keySize > 0, "Invalid key size: %d", keySize);
        this.keySize = keySize;
        Objects.requireNonNull(digest, "No key digest provided");

        int x = FLDSIZE_X / 2;
        int y = FLDSIZE_Y / 2;
        int len = AUGMENTATION_STRING.length() - 1;
        for (int i = 0; i < digest.length; i++) {
            /* each byte conveys four 2-bit move commands */
            int input = digest[i] & 0xFF;
            for (int b = 0; b < 4; b++) {
                /* evaluate 2 bit, rest is shifted later */
                x += ((input & 0x1) != 0) ? 1 : -1;
                y += ((input & 0x2) != 0) ? 1 : -1;

                /* assure we are still in bounds */
                x = Math.max(x, 0);
                y = Math.max(y, 0);
                x = Math.min(x, FLDSIZE_X - 1);
                y = Math.min(y, FLDSIZE_Y - 1);

                /* augment the field */
                if (field[x][y] < (len - 2)) {
                    field[x][y]++;
                }
                input = input >> 2;
            }
        }

        /* mark starting point and end point */
        field[FLDSIZE_X / 2][FLDSIZE_Y / 2] = (char) (len - 1);
        field[x][y] = (char) len;
    }

    /**
     * @return The algorithm that was used to generate the key - e.g., &quot;RSA&quot;, &quot;DSA&quot;, &quot;EC&quot;.
     */
    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    /**
     * Outputs the generated random art
     *
     * @param  <A>         The {@link Appendable} output writer
     * @param  sb          The writer
     * @return             The updated writer instance
     * @throws IOException If failed to write the combined result
     */
    public <A extends Appendable> A append(A sb) throws IOException {
        // Upper border
        String s = String.format("+--[%4s %4d]", getAlgorithm(), getKeySize());
        sb.append(s);
        for (int index = s.length(); index <= FLDSIZE_X; index++) {
            sb.append('-');
        }
        sb.append('+');
        sb.append('\n');

        // contents
        int len = AUGMENTATION_STRING.length() - 1;
        for (int y = 0; y < FLDSIZE_Y; y++) {
            sb.append('|');
            for (int x = 0; x < FLDSIZE_X; x++) {
                char ch = field[x][y];
                sb.append(AUGMENTATION_STRING.charAt(Math.min(ch, len)));
            }
            sb.append('|');
            sb.append('\n');
        }

        // lower border
        sb.append('+');
        for (int index = 0; index < FLDSIZE_X; index++) {
            sb.append('-');
        }

        sb.append('+');
        sb.append('\n');
        return sb;
    }

    @Override
    public String toString() {
        try {
            return append(new StringBuilder((FLDSIZE_X + 4) * (FLDSIZE_Y + 3))).toString();
        } catch (IOException e) {
            return e.getClass().getSimpleName(); // unexpected
        }
    }

    /**
     * Combines the arts in a user-friendly way so they are aligned with each other
     *
     * @param  separator The separator to use between the arts - if empty char ('\0') then no separation is done
     * @param  arts      The {@link KeyRandomArt}s to combine - ignored if {@code null}/empty
     * @return           The combined result
     */
    public static String combine(char separator, Collection<? extends KeyRandomArt> arts) {
        if (GenericUtils.isEmpty(arts)) {
            return "";
        }

        try {
            return combine(new StringBuilder(arts.size() * (FLDSIZE_X + 4) * (FLDSIZE_Y + 3)), separator, arts).toString();
        } catch (IOException e) {
            return e.getClass().getSimpleName(); // unexpected
        }
    }

    /**
     * Creates the combined representation of the random art entries for the provided keys
     *
     * @param  session   The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                   within a session context (e.g., offline tool or session unknown).
     * @param  separator The separator to use between the arts - if empty char ('\0') then no separation is done
     * @param  provider  The {@link KeyIdentityProvider} - ignored if {@code null} or has no keys to provide
     * @return           The combined representation
     * @throws Exception If failed to extract or combine the entries
     * @see              #combine(SessionContext, Appendable, char, KeyIdentityProvider)
     */
    public static String combine(
            SessionContext session, char separator, KeyIdentityProvider provider)
            throws Exception {
        return combine(session, new StringBuilder(4 * (FLDSIZE_X + 4) * (FLDSIZE_Y + 3)), separator, provider).toString();
    }

    /**
     * Appends the combined random art entries for the provided keys
     *
     * @param  <A>       The {@link Appendable} output writer
     * @param  session   The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                   within a session context (e.g., offline tool or session unknown).
     * @param  sb        The writer
     * @param  separator The separator to use between the arts - if empty char ('\0') then no separation is done
     * @param  provider  The {@link KeyIdentityProvider} - ignored if {@code null} or has no keys to provide
     * @return           The updated writer instance
     * @throws Exception If failed to extract or write the entries
     * @see              #generate(SessionContext, KeyIdentityProvider)
     * @see              #combine(Appendable, char, Collection)
     */
    public static <A extends Appendable> A combine(
            SessionContext session, A sb, char separator, KeyIdentityProvider provider)
            throws Exception {
        return combine(sb, separator, generate(session, provider));
    }

    /**
     * Extracts and generates random art entries for all key in the provider
     *
     * @param  session   The {@link SessionContext} for invoking this load command - may be {@code null} if not invoked
     *                   within a session context (e.g., offline tool or session unknown).
     * @param  provider  The {@link KeyIdentityProvider} - ignored if {@code null} or has no keys to provide
     * @return           The extracted {@link KeyRandomArt}s
     * @throws Exception If failed to extract the entries
     * @see              KeyIdentityProvider#loadKeys(SessionContext)
     */
    public static Collection<KeyRandomArt> generate(
            SessionContext session, KeyIdentityProvider provider)
            throws Exception {
        Iterable<KeyPair> keys = (provider == null) ? null : provider.loadKeys(session);
        Iterator<KeyPair> iter = (keys == null) ? null : keys.iterator();
        if ((iter == null) || (!iter.hasNext())) {
            return Collections.emptyList();
        }

        Collection<KeyRandomArt> arts = new LinkedList<>();
        do {
            KeyPair kp = iter.next();
            KeyRandomArt a = new KeyRandomArt(kp.getPublic());
            arts.add(a);
        } while (iter.hasNext());

        return arts;
    }

    /**
     * Combines the arts in a user-friendly way so they are aligned with each other
     *
     * @param  <A>         The {@link Appendable} output writer
     * @param  sb          The writer
     * @param  separator   The separator to use between the arts - if empty char ('\0') then no separation is done
     * @param  arts        The {@link KeyRandomArt}s to combine - ignored if {@code null}/empty
     * @return             The updated writer instance
     * @throws IOException If failed to write the combined result
     */
    public static <A extends Appendable> A combine(A sb, char separator, Collection<? extends KeyRandomArt> arts)
            throws IOException {
        if (GenericUtils.isEmpty(arts)) {
            return sb;
        }

        List<String[]> allLines = new ArrayList<>(arts.size());
        int numLines = -1;
        for (KeyRandomArt a : arts) {
            String s = a.toString();
            String[] lines = GenericUtils.split(s, '\n');
            if (numLines <= 0) {
                numLines = lines.length;
            } else {
                if (numLines != lines.length) {
                    throw new StreamCorruptedException(
                            "Mismatched lines count: expected=" + numLines + ", actual=" + lines.length);
                }
            }

            for (int index = 0; index < lines.length; index++) {
                String l = lines[index];
                if ((l.length() > 0) && (l.charAt(l.length() - 1) == '\r')) {
                    l = l.substring(0, l.length() - 1);
                    lines[index] = l;
                }
            }

            allLines.add(lines);
        }

        for (int row = 0; row < numLines; row++) {
            for (int index = 0; index < allLines.size(); index++) {
                String[] lines = allLines.get(index);
                String l = lines[row];
                sb.append(l);
                if ((index > 0) && (separator != '\0')) {
                    sb.append(separator);
                }
            }
            sb.append('\n');
        }

        return sb;
    }
}
