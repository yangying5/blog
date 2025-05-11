package com.dumpMemory;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.io.IOUtils;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class Template64 extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private Module module;
    public long count = 0;
    public long moduleBase = 0xBEC4A000L;   // todo  目标so 基地址

    Template64() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .setProcessName("packName")   // todo  packageName
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getBackend().registerEmuCountHook(10000); // 设置执行多少条指令切换一次线程
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/****.apk"));  // todo  apk path
        vm.setJni(this);
        vm.setVerbose(true);
        DalvikModule dm = vm.loadLibrary("soName", false);  // todo  soname
        module = dm.getModule();

        patch();
//        emulator.traceWrite(0xe20d9da0L + 0x3F, 0xe20d9da0L + 0x3F);
    }


    int UNICORN_PAGE_SIZE = 0x1000;

    private long align_page_down(long x){
        return x & ~(UNICORN_PAGE_SIZE - 1);
    }
    private long align_page_up(long x){
        return (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE - 1);
    }

    private void map_segment(long address, long size, int perms){

        long mem_start = address;
        long mem_end = address + size;
        long mem_start_aligned = align_page_down(mem_start);
        long mem_end_aligned = align_page_up(mem_end);

        if (mem_start_aligned < mem_end_aligned){
            emulator.getBackend().mem_map(mem_start_aligned, mem_end_aligned - mem_start_aligned, perms);
        }
    }

    private void load_context(String dump_dir) throws IOException, DataFormatException, IOException {
        Backend backend = emulator.getBackend();
//        Memory memory = emulator.getMemory();
        String context_file = dump_dir + "\\" + "_index.json";
        InputStream is = new FileInputStream(context_file);
        String jsonTxt = IOUtils.toString(is, "UTF-8");
        JSONObject context = JSONObject.parseObject(jsonTxt);
        JSONObject regs = context.getJSONObject("regs");

        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, Long.parseUnsignedLong(regs.getString("x0").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X1, Long.parseUnsignedLong(regs.getString("x1").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X2, Long.parseUnsignedLong(regs.getString("x2").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X3, Long.parseUnsignedLong(regs.getString("x3").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X4, Long.parseUnsignedLong(regs.getString("x4").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X5, Long.parseUnsignedLong(regs.getString("x5").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X6, Long.parseUnsignedLong(regs.getString("x6").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X7, Long.parseUnsignedLong(regs.getString("x7").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X8, Long.parseUnsignedLong(regs.getString("x8").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X9, Long.parseUnsignedLong(regs.getString("x9").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X10, Long.parseUnsignedLong(regs.getString("x10").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X11, Long.parseUnsignedLong(regs.getString("x11").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X12, Long.parseUnsignedLong(regs.getString("x12").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X13, Long.parseUnsignedLong(regs.getString("x13").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X14, Long.parseUnsignedLong(regs.getString("x14").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X15, Long.parseUnsignedLong(regs.getString("x15").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X16, Long.parseUnsignedLong(regs.getString("x16").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X17, Long.parseUnsignedLong(regs.getString("x17").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X18, Long.parseUnsignedLong(regs.getString("x18").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X19, Long.parseUnsignedLong(regs.getString("x19").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X20, Long.parseUnsignedLong(regs.getString("x20").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X21, Long.parseUnsignedLong(regs.getString("x21").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X22, Long.parseUnsignedLong(regs.getString("x22").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X23, Long.parseUnsignedLong(regs.getString("x23").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X24, Long.parseUnsignedLong(regs.getString("x24").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X25, Long.parseUnsignedLong(regs.getString("x25").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X26, Long.parseUnsignedLong(regs.getString("x26").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X27, Long.parseUnsignedLong(regs.getString("x27").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X28, Long.parseUnsignedLong(regs.getString("x28").substring(2), 16));

        backend.reg_write(Arm64Const.UC_ARM64_REG_FP, Long.parseUnsignedLong(regs.getString("fp").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR, Long.parseUnsignedLong(regs.getString("lr").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP, Long.parseUnsignedLong(regs.getString("sp").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, Long.parseUnsignedLong(regs.getString("pc").substring(2), 16));
        backend.reg_write(ArmConst.UC_ARM_REG_CPSR, Long.parseUnsignedLong(regs.getString("cpsr").substring(2), 16));

        backend.reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, 0x300000L);
        backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, 0x0000007aa84f8588L);  // todo 如果涉及系统寄存器，需要获取

//        好像不设置这个也不会有什么影响
//        memory.setStackPoint(Long.parseUnsignedLong(regs.getString("sp").substring(2), 16));

        JSONArray segments = context.getJSONArray("segments");

        for (int i = 0; i < segments.size(); i++) {
            JSONObject segment = segments.getJSONObject(i);
            String path = segment.getString("name");
            long start = segment.getLong("start");
            long end = segment.getLong("end");
            String content_file = segment.getString("content_file");
            JSONObject permissions = segment.getJSONObject("permissions");
            int perms = 0;
            if (permissions.getBoolean("r")){
                perms |= UnicornConst.UC_PROT_READ;
            }
            if (permissions.getBoolean("w")){
                perms |= UnicornConst.UC_PROT_WRITE;
            }
            if (permissions.getBoolean("x")){
                perms |= UnicornConst.UC_PROT_EXEC;
            }

            String[] paths = path.split("/");
            String module_name = paths[paths.length - 1];

            List<String> white_list = Arrays.asList(new String[]{"liboasiscore.so", "libc.so", "****.bin"});  // todo

            if (white_list.contains(module_name) || white_list.contains(content_file)){
                System.out.println("enter module: " + module_name);
                int size = (int)(end - start);

                map_segment(start, size, perms);
                String content_file_path = dump_dir + "\\" + content_file;
                System.out.println(content_file_path);
                File content_file_f = new File(content_file_path);
                if (content_file_f.exists()){
                    InputStream content_file_is = new FileInputStream(content_file_path);
                    byte[] content_file_buf = IOUtils.toByteArray(content_file_is);

                    // 解压
                    Inflater decompresser = new Inflater();
                    decompresser.setInput(content_file_buf, 0, content_file_buf.length);
                    byte[] result = new byte[size];
                    int resultLength = decompresser.inflate(result);
                    decompresser.end();

                    backend.mem_write(start, result);
                }
                else {
                    System.out.println("not exists path=" + path);
                    byte[] fill_mem = new byte[size];
                    Arrays.fill( fill_mem, (byte) 0 );
                    backend.mem_write(start, fill_mem);
                }

            }
        }

    }

    public void recordTarget(){
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if(address >= 0xBEC4A000L && address <= 0xBED28000L){
                    count +=1;
                }
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, 1,0, null);
    }

    private void callTarget() {
//        emulator.traceCode();
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        DvmObject<?> thiz = vm.resolveClass("com/aliyun/TigerTally/TigerTallyAPI").newObject(null);  // todo 目标类
        list.add(vm.addLocalObject(thiz));
        list.add(1);
//        传参
        ByteArray barr = new ByteArray(vm, "b6562dcf78d8-c4a7-43b1-8a12-b3872cce".getBytes(StandardCharsets.UTF_8));
//        ByteArray barr = new ByteArray(vm, UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
        list.add(vm.addLocalObject(barr));

//        这里获取 dump 时的 pc 地址作为模拟执行起始地址
        long ctx_addr = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        System.out.println("addr：" + ctx_addr);
//        开始模拟执行
        Number result = Module.emulateFunction(emulator, ctx_addr, list.toArray());
        String ret = vm.getObject(result.intValue()).getValue().toString();
        System.out.println("result:"+ret);
        System.out.println("length:"+ret.length());
        Inspector.inspect(ret.getBytes(StandardCharsets.UTF_8), "result");
    }

    public static void main(String[] args) {
        Template64 t = new Template64();
        try {
            t.load_context("unidbg-android/src/test/resources/dumpMemory/nike/DumpContext");  // todo dump path
            t.recordTarget();
            t.callTarget();
            System.out.println(t.count);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (DataFormatException e) {
            e.printStackTrace();
        }
    }

    public void patch() {
        // malloc BE10E000
        emulator.attach().addBreakPoint(0x121D8L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("malloc").getAddress());
                return true;
            }
        });

        // memcpy
        emulator.attach().addBreakPoint(0x12250L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext registerContext = emulator.getContext();
                int length = registerContext.getIntArg(2);
                UnidbgPointer src = registerContext.getPointerArg(0);
                UnidbgPointer r1 = registerContext.getPointerArg(1);
                Inspector.inspect(r1.getByteArray(0, length), "memcpy src" + r1 + " dest" + src);
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("memcpy").getAddress());
                return true;
            }
        });

        // free
        emulator.attach().addBreakPoint(0x1225CL + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, emulator.getContext().getLR());
                return true;
            }
        });

        // memset
        emulator.attach().addBreakPoint(0x12478L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext registerContext = emulator.getContext();
                int num = registerContext.getIntArg(1);
                int length = registerContext.getIntArg(2);
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R1, length);
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_R2, num);
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("memset").getAddress());
                return true;
            }
        });

        // gettimeofday
        emulator.attach().addBreakPoint(0x123A0L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("gettimeofday").getAddress());
                return true;
            }
        });

        // sprintf
        emulator.attach().addBreakPoint(0x123B8L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext registerContext = emulator.getContext();
                System.out.println("call sprintf");
                System.out.println(registerContext.getPointerArg(1).getString(0));
                System.out.println(Long.toHexString(registerContext.getIntArg(2)));
                System.out.println(Long.toHexString(registerContext.getLRPointer().peer - moduleBase));
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("sprintf").getAddress());
                return true;
            }
        });

        // memmove
        emulator.attach().addBreakPoint(0x1228CL + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                RegisterContext registerContext = emulator.getContext();
                int length = registerContext.getIntArg(2);
                UnidbgPointer str1 = registerContext.getPointerArg(0);
                UnidbgPointer str2 = registerContext.getPointerArg(1);
                Inspector.inspect(str2.getByteArray(0, length), "memmove src" + str2 + " dest" + str1);
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("memmove").getAddress());
                return true;
            }
        });

        // strlent
        emulator.attach().addBreakPoint(0x12178L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("strlen").getAddress());
                return true;
            }
        });

        // memclr
        emulator.attach().addBreakPoint(0x12220L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, emulator.getContext().getLR());
                return true;
            }
        });

        // realloc
        emulator.attach().addBreakPoint(0x125A4L + moduleBase, new BreakPointCallback() {
            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                emulator.getBackend().reg_write(ArmConst.UC_ARM_REG_PC, module.findSymbolByName("realloc").getAddress());
                return true;
            }
        });
    }

}

