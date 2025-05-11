package com.aikucun.akapp;

import capstone.api.Instruction;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.listener.TraceCodeListener;
import com.github.unidbg.memory.Memory;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class MXSecurityDump extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    public long moduleBase;
    public Module module;

    public MXSecurityDump() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .setProcessName("com.aikucun.akapp")
                .build();
        emulator.getBackend().registerEmuCountHook(10000); // 设置执行多少条指令切换一次线程
        emulator.getSyscallHandler().setVerbose(true);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/aikucun/dump/aikucun_6.3.2.apk"));
        vm.setVerbose(true);
        vm.setJni(this);
        moduleBase = 0x6ee85ca000L;  // 地址来自于dump时展示so首地址
        // 手动将 SO 对应的内存写到 Unidbg 虚拟环境里
        loadBinary("unidbg-android/src/test/resources/aikucun/dump/libmx.so", moduleBase);
        loadBinary("unidbg-android/src/test/resources/aikucun/dump/6f5d895d10.bin", 0x6f5d895d10L);
        DalvikModule dalvikModule = vm.loadLibrary("mx", false);
        module = dalvikModule.getModule();
        emulator.traceCode();
    }

    private long align_page_up(long x){
        return (x + 0x1000 - 1) & -0x1000;
    }

    private long align_page_down(long x){
        return x & -0x1000;
    }

    public void loadBinary(String path, long address){
        Path binaryPath = Paths.get(path);
        byte[] data = new byte[0];
        try {
            data = Files.readAllBytes(binaryPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
        long size = data.length;
        long mem_start = address;
        long mem_end = address + size;
        long mem_start_aligned = align_page_down(mem_start);
        long mem_end_aligned = align_page_up(mem_end);

        if (mem_start_aligned < mem_end_aligned){
            emulator.getBackend().mem_map(mem_start_aligned, mem_end_aligned - mem_start_aligned, UnicornConst.UC_PROT_ALL);
        }
        emulator.getBackend().mem_write(address, data);
    }


    public void patchOne(long addr){
        emulator.attach().addBreakPoint(addr, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, module.base + (addr - moduleBase));
                return true;
            }
        });
    }

    public void patchLib(){
        patchOne(0x6ee85d73d0L);
        patchOne(0x6ee85d7640L);
        patchOne(0x6ee85d7680L);
        patchOne(0x6ee85d76a0L);
        patchOne(0x6ee85d7430L);
        patchOne(0x6ee85d7620L);
    }

    public void call(){
        StringObject arg1 = new StringObject(vm, "https://zuul.aikucun.com/aggregation-center-facade/api/app/search/product/image/switch?" +
                "appid=38741001&did=6d2fe7c7702721c6b797cf22ec8f5f58&noncestr=4b373c&timestamp=1662394452&zuul=1");
        StringObject arg2 = new StringObject(vm, "4b373c");
        StringObject arg3 = new StringObject(vm, "1662394452");
        Number number = Module.emulateFunction(emulator, 0x6ee85ca000L + 0xe2ec, vm.getJNIEnv(), 0, vm.addLocalObject(arg1), vm.addLocalObject(arg2), vm.addLocalObject(arg3));
        String result = vm.getObject(number.intValue()).getValue().toString();
        System.out.println("result:"+result);
    }

    public static void main(String[] args) {
        MXSecurityDump msDump = new MXSecurityDump();
        msDump.patchLib();
        msDump.call();
    }
}

