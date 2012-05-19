package org.apache.sshd.util;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.util.Buffer;

import java.io.IOException;

public class BogusChannel extends AbstractChannel {

    @Override
    protected void doWriteData(byte[] data, int off, int len) throws IOException {
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
    }

    @Override
    protected void sendWindowAdjust(int len) throws IOException {
    }

    public OpenFuture open(int recipient, int rwsize, int rmpsize, Buffer buffer) {
        return new DefaultOpenFuture(this.lock);
    }

    public void handleOpenSuccess(int recipient, int rwsize, int rmpsize, Buffer buffer) throws IOException {
    }

    public void handleOpenFailure(Buffer buffer) throws IOException {
    }

}
