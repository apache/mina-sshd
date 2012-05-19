package org.apache.sshd.common.channel;

import org.apache.sshd.util.BogusChannel;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class ChannelPipedInputStreamTest {

    @Test
    public void testAvailable() throws Exception {
        Window window = new Window(new BogusChannel(), null, true, true);
        ChannelPipedInputStream stream = new ChannelPipedInputStream(window);

        byte[] b = "test".getBytes();
        stream.receive(b, 0, b.length);
        assertEquals(b.length, stream.available());

        stream.eof();
        assertEquals(b.length, stream.available());

        final byte[] readBytes = new byte[50];
        assertEquals(b.length, stream.read(readBytes));
        assertStreamEquals(b, readBytes);
        assertEquals(-1, stream.available());
    }

    private void assertStreamEquals(byte[] expected, byte[] read) {
        if (expected.length > read.length) {
            fail("Less bytes than expected: " + Arrays.toString(expected) + " but got: " + Arrays.toString(read));
        } else {
            assertArrayEquals(expected, Arrays.copyOf(read, expected.length));
            for (int i = expected.length; i < read.length; i++) {
                assertEquals('\0', read[i]);
            }
        }
    }

}
