package org.apache.sshd.server.keyprovider;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

public class AbstractGeneratorHostKeyProviderTest {

    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void testOverwriteKey() throws Exception {
        File keyPairFile = temporaryFolder.newFile();

        TestProvider provider = new TestProvider(keyPairFile);
        provider.loadKeys();
        assertEquals(1, provider.getWriteCount());

        provider = new TestProvider(keyPairFile);
        provider.setOverwriteAllowed(false);
        provider.loadKeys();
        assertEquals(0, provider.getWriteCount());
    }

    private class TestProvider extends AbstractGeneratorHostKeyProvider {
        private final AtomicInteger writes = new AtomicInteger(0);

        private TestProvider(File file) {
            super(file.getAbsolutePath(), "DSA", 512);
        }

        @Override
        protected KeyPair doReadKeyPair(InputStream is) throws Exception {
            return null;
        }

        @Override
        protected void doWriteKeyPair(KeyPair kp, OutputStream os) throws Exception {
            writes.incrementAndGet();
        }

        public int getWriteCount() {
            return writes.get();
        }
    }

}