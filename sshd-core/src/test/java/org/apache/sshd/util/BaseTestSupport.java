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
package org.apache.sshd.util;

import java.io.File;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class BaseTestSupport extends Assert {
    @Rule public final TestWatcher rule = new TestWatcher() {
            // TODO consider using a ThreadLocal storage for the start time - provided
            //      the code is assured to call starting/finished on the same thread
            private long startTime;
    
            @Override
            protected void starting(Description description) {
                System.out.println("\nStarting " + description.getClassName() + ":" + description.getMethodName() + "...\n");
                startTime = System.currentTimeMillis();
            }
    
            @Override
            protected void finished(Description description) {
                long duration = System.currentTimeMillis() - startTime;
                System.out.println("\nFinished " + description.getClassName() + ":" + description.getMethodName() + " in " + duration + " ms\n");
            }
        };
    @Rule public final TestName TEST_NAME_HOLDER = new TestName();

    protected BaseTestSupport() {
    	super();
    }

    public final String getCurrentTestName() {
        return TEST_NAME_HOLDER.getMethodName();
    }

    /* ------------------- Useful extra test helpers ---------------------- */

    public static String shuffleCase(CharSequence cs) {
        if (GenericUtils.isEmpty(cs)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(cs.length());
        for (int index = 0; index < cs.length(); index++) {
            char ch = cs.charAt(index);
            double v = Math.random();
            if (Double.compare(v, 0.3d) < 0) {
                ch = Character.toUpperCase(ch);
            } else if ((Double.compare(v, 0.3d) >= 0) && (Double.compare(v, 0.6d) < 0)) {
                ch = Character.toLowerCase(ch);
            }
            sb.append(ch);
        }

        return sb.toString();
    }

    /* ----------------------- Useful extra assertions --------------------- */

    public static File assertHierarchyTargetFolderExists(File folder) {
        if (!folder.exists()) {
            assertTrue("Failed to create hierarchy of " + folder.getAbsolutePath(), folder.mkdirs());
        }
        
        return folder;
    }
    
    public static void assertObjectInstanceOf(String message, Class<?> expected, Object obj) {
        assertNotNull(message + " - no actual object", obj);
        
        Class<?>    actual=obj.getClass();
        if (!expected.isAssignableFrom(actual)) {
            fail(message + " - actual object type (" + actual.getName() + ") incompatible with expected (" + expected.getName() + ")");
        }
    }
    
    public static <E> void assertListEquals(String message, List<? extends E> expected, List<? extends E> actual) {
        int expSize=GenericUtils.size(expected), actSize=GenericUtils.size(actual);
        assertEquals(message + "[size]", expSize, actSize);
        
        for (int index=0; index < expSize; index++) {
            E expValue=expected.get(index), actValue=actual.get(index);
            assertEquals(message + "[" + index + "]", expValue, actValue);
        }
    }

    public static void assertKeyPairEquals(String message, KeyPair expected, KeyPair actual) {
        assertKeyEquals(message + "[public]", expected.getPublic(), actual.getPublic());
        assertKeyEquals(message + "[private]", expected.getPrivate(), actual.getPrivate());
    }

    public static final <T extends Key> void assertKeyEquals(String message, T expected, T actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[algorithm]", expected.getAlgorithm(), actual.getAlgorithm());

        if (expected instanceof RSAPublicKey) {
            assertRSAPublicKeyEquals(message, RSAPublicKey.class.cast(expected), RSAPublicKey.class.cast(actual));
        } else if (expected instanceof DSAPublicKey) {
            assertDSAPublicKeyEquals(message, DSAPublicKey.class.cast(expected), DSAPublicKey.class.cast(actual));
        } else if (expected instanceof ECPublicKey) {
            assertECPublicKeyEquals(message, ECPublicKey.class.cast(expected), ECPublicKey.class.cast(actual));
        } else if (expected instanceof RSAPrivateKey) {
            assertRSAPrivateKeyEquals(message, RSAPrivateKey.class.cast(expected), RSAPrivateKey.class.cast(actual));
        } else if (expected instanceof ECPrivateKey) {
            assertECPrivateKeyEquals(message, ECPrivateKey.class.cast(expected), ECPrivateKey.class.cast(actual));
        }
        assertArrayEquals(message + "[encdoded-data]", expected.getEncoded(), actual.getEncoded());
    }

    public static final void assertRSAPublicKeyEquals(String message, RSAPublicKey expected, RSAPublicKey actual) {
        if (expected == actual) {
            return;
        }
        
        assertEquals(message + "[e]", expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(message + "[n]", expected.getModulus(), actual.getModulus());
    }

    public static final void assertDSAPublicKeyEquals(String message, DSAPublicKey expected, DSAPublicKey actual) {
        if (expected == actual) {
            return;
        }
        
        assertEquals(message + "[y]", expected.getY(), actual.getY());
        assertDSAParamsEquals(message + "[params]", expected.getParams(), actual.getParams());
    }

    public static final void assertECPublicKeyEquals(String message, ECPublicKey expected, ECPublicKey actual) {
        if (expected == actual) {
            return;
        }

        assertECPointEquals(message + "[W]", expected.getW(), actual.getW());
        assertECParameterSpecEquals(message, expected, actual);
    }

    public static final void assertRSAPrivateKeyEquals(String message, RSAPrivateKey expected, RSAPrivateKey actual) {
        if (expected == actual) {
            return;
        }
        
        assertEquals(message + "[d]", expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(message + "[n]", expected.getModulus(), actual.getModulus());
    }

    public static final void assertDSAPrivateKeyEquals(String message, DSAPrivateKey expected, DSAPrivateKey actual) {
        if (expected == actual) {
            return;
        }
        
        assertEquals(message + "[x]", expected.getX(), actual.getX());
        assertDSAParamsEquals(message + "[params]", expected.getParams(), actual.getParams());
    }

    public static final void assertDSAParamsEquals(String message, DSAParams expected, DSAParams actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[g]", expected.getG(), actual.getG());
        assertEquals(message + "[p]", expected.getP(), actual.getP());
        assertEquals(message + "[q]", expected.getQ(), actual.getQ());
    }

    public static final void assertECPrivateKeyEquals(String message, ECPrivateKey expected, ECPrivateKey actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[S]", expected.getS(), actual.getS());
        assertECParameterSpecEquals(message, expected, actual);
    }

    public static final void assertECParameterSpecEquals(String message, ECKey expected, ECKey actual) {
        if (expected == actual) {
            return;
        }
        assertECParameterSpecEquals(message, expected.getParams(), actual.getParams());
    }

    public static final void assertECParameterSpecEquals(String message, ECParameterSpec expected, ECParameterSpec actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[order]", expected.getOrder(), actual.getOrder());
        assertEquals(message + "[cofactor]", expected.getCofactor(), actual.getCofactor());
        assertECPointEquals(message + "[generator]", expected.getGenerator(), actual.getGenerator());
        assertCurveEquals(message + "[curve]", expected.getCurve(), actual.getCurve());
    }

    public static final void assertCurveEquals(String message, EllipticCurve expected, EllipticCurve actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[A]", expected.getA(), actual.getA());
        assertEquals(message + "[B]", expected.getB(), actual.getB());
        assertArrayEquals(message + "[seed]", expected.getSeed(), actual.getSeed());
        assertECFieldEquals(message + "[field]", expected.getField(), actual.getField());
    }

    public static final void assertECFieldEquals(String message, ECField expected, ECField actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[size]", expected.getFieldSize(), actual.getFieldSize());
    }

    public static final void assertECPointEquals(String message, ECPoint expected, ECPoint actual) {
        if (expected == actual) {
            return;
        }

        assertEquals(message + "[x]", expected.getAffineX(), actual.getAffineX());
        assertEquals(message + "[y]", expected.getAffineY(), actual.getAffineY());
    }
}
