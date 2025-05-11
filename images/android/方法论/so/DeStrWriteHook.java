package ollvm;


import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.listener.TraceWriteListener;
import javafx.util.Pair;
import trace.OtherTools;
import unicorn.Unicorn;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;


public class DeStrWriteHook implements WriteHook {

    private final boolean read;

    public DeStrWriteHook(boolean read) {
        this.read = read;
    }
    PrintStream redirect;
    TraceWriteListener traceWriteListener;
    public Map<Long, Pair<byte[],byte[]>> dstr_datas=new HashMap<Long, Pair<byte[],byte[]>>();

    /**
     * long类型转byte[] (大端)
     * @param n
     * @return
     */
    public static byte[] longToBytesBig(long n) {
        byte[] b = new byte[8];
        b[7] = (byte) (n & 0xff);
        b[6] = (byte) (n >> 8  & 0xff);
        b[5] = (byte) (n >> 16 & 0xff);
        b[4] = (byte) (n >> 24 & 0xff);
        b[3] = (byte) (n >> 32 & 0xff);
        b[2] = (byte) (n >> 40 & 0xff);
        b[1] = (byte) (n >> 48 & 0xff);
        b[0] = (byte) (n >> 56 & 0xff);
        return b;
    }
    /**
     * long类型转byte[] (小端)
     * @param n
     * @return
     */
    public static byte[] longToBytesLittle(long n) {
        byte[] b = new byte[8];
        b[0] = (byte) (n & 0xff);
        b[1] = (byte) (n >> 8  & 0xff);
        b[2] = (byte) (n >> 16 & 0xff);
        b[3] = (byte) (n >> 24 & 0xff);
        b[4] = (byte) (n >> 32 & 0xff);
        b[5] = (byte) (n >> 40 & 0xff);
        b[6] = (byte) (n >> 48 & 0xff);
        b[7] = (byte) (n >> 56 & 0xff);
        return b;
    }

    @Override
    public void hook(Backend backend, long address, int size, long value, Object user) {
        if (read) {
            return;
        }
        try {
            Emulator<?> emulator = (Emulator<?>) user;
            if (traceWriteListener == null || traceWriteListener.onWrite(emulator, address, size, value)) {
                //将写入的地址和写入的数据保存下来
                byte[] writedata=longToBytesLittle(value);
                byte[] resizeWriteData=new byte[size];
                byte[] buff=emulator.getBackend().mem_read(address,size);
                String src= OtherTools.byteToString(buff);
                String dest= OtherTools.byteToString(resizeWriteData);
                if(!src.equals(dest)){
                    System.arraycopy(writedata,0,resizeWriteData,0,size);
                    dstr_datas.put(address,new Pair(resizeWriteData,buff));
                }
            }
        } catch (BackendException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void onAttach(Unicorn.UnHook unHook) {

    }

    @Override
    public void detach() {

    }
}