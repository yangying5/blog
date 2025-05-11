import os
import sys
import json
import zlib
import shutil
import hashlib
import logging
import zipfile

from pathlib import Path
from datetime import datetime

from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from lldb import *

import lldb


def __lldb_init_module(debugger: 'SBDebugger', internal_dict: dict):
    debugger.HandleCommand('command script add -f lldb_dumper.helloworld hello')
    debugger.HandleCommand('command script add -f lldb_dumper.dump_context dumpctx')


GLOBAL_LOGGERS = {}
logger = None  # type: logging.Logger


def setup_logger(log_tag: str, log_path: Path, first_call: bool = False) -> logging.Logger:
    '''
    输出的信息太多 Terminal可能不全 记录到日志文件
    '''
    logger = GLOBAL_LOGGERS.get(log_tag)
    if logger:
        return logger

    logger = logging.getLogger(log_tag)
    GLOBAL_LOGGERS[log_tag] = logger

    # 避免重新载入脚本时重复输出
    if first_call and logger.hasHandlers():
        logger.handlers.clear()

    # 设置所有 handler 的日志等级
    logger.setLevel(logging.DEBUG)

    # 添加终端 handler 只打印原始信息
    formatter = logging.Formatter('%(message)s')
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # 添加文件 handler 记录详细时间和内容
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    fh = logging.FileHandler(log_path.as_posix(), encoding='utf-8', delay=True)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger


def dump_arch_info(target: 'SBTarget'):
    triple = target.GetTriple()
    logger.debug(f'[dump_arch_info] triple => {triple}')
    # 'aarch64', 'unknown', 'linux', 'android'
    arch, vendor, sys, abi = triple.split('-')
    if arch == 'aarch64' or arch == 'arm64':
        return 'arm64le'
    elif arch == 'aarch64_be':
        return 'arm64be'
    elif arch == 'armeb':
        return 'armbe'
    elif arch == 'arm':
        return 'armle'
    else:
        return ''


def dump_regs(frame: 'SBFrame'):
    regs = {}  # type: Dict[str, int]
    # 实际类型是 SBValueList 但是这样 type hint 没有效果
    registers = None  # type: List[SBValue]
    for registers in frame.GetRegisters():
        # - General Purpose Registers
        # - Floating Point Registers
        logger.debug(f'registers name => {registers.GetName()}')
        for register in registers:
            register_name = register.GetName()
            # 直接获取 SBValue 拿到的值通常得到的是贴近人类可读的字符串
            # 但是对于浮点寄存器来说 我们应该拿到最为精确的值
            # 可以指定为 lldb.eFormatUnsigned 这样就直接是最完整的数值了
            # 但是类型依然是字符串 在使用时还需要一次转换
            # 因此这里干脆指定为 lldb.eFormatHex 更加符合逆向人员的阅读习惯
            # https://lldb.llvm.org/python_api_enums.html#format
            register.SetFormat(lldb.eFormatHex)
            register_value = register.GetValue()
            regs[register_name] = register_value
    logger.info(f'regs => {json.dumps(regs, ensure_ascii=False, indent=4)}')
    return regs


def get_section_info(target: 'SBTarget', section: 'SBSection'):
    name = section.name if section.name is not None else ''
    if section.GetParent().name is not None:
        name = section.GetParent().name + '.' + section.name

    module_name = section.addr.module.file.GetFilename()
    module_name = module_name if module_name is not None else ''
    long_name = module_name + '.' + name

    load_addr = section.addr.GetLoadAddress(target)

    return load_addr, (load_addr + section.size), section.size, long_name


def dump_memory_info(target: 'SBTarget'):
    logger.debug('start dump_memory_info')
    sections = []
    # 先查找全部分段信息
    for module in target.module_iter():
        module: SBModule
        for section in module.section_iter():
            section: SBSection
            module_name = module.file.GetFilename()
            start, end, size, name = get_section_info(target, section)
            section_info = {
                'module': module_name,
                'start': start,
                'end': end,
                'size': size,
                'name': name,
            }
            # size 好像有负数的情况 不知道是什么情况
            logger.info(f'Appending: {name}')
            sections.append(section_info)
    return sections


def dump_memory(process: 'SBProcess', dump_path: Path, black_list: Dict[str, List[str]], max_seg_size: int):
    logger.debug('start dump memory')
    memory_list = []
    mem_info = lldb.SBMemoryRegionInfo()
    start_addr = -1
    next_region_addr = 0
    while next_region_addr > start_addr:
        # 从内存起始位置开始获取内存信息
        err = process.GetMemoryRegionInfo(next_region_addr, mem_info)  # type: SBError
        if not err.success:
            logger.warning(f'GetMemoryRegionInfo failed, {err}, break')
            break
        # 获取当前位置的结尾地址
        next_region_addr = mem_info.GetRegionEnd()
        # 如果超出上限 结束遍历
        if next_region_addr >= sys.maxsize:
            logger.info(f'next_region_addr:0x{next_region_addr:x} >= sys.maxsize, break')
            break
        # 获取当前这块内存的起始地址和结尾地址
        start = mem_info.GetRegionBase()
        end = mem_info.GetRegionEnd()
        # 很多内存块没有名字 预设一个
        region_name = 'UNKNOWN'
        # 记录分配了的内存
        if mem_info.IsMapped():
            name = mem_info.GetName()
            if name is None:
                name = ''
            mem_info_obj = {
                'start': start,
                'end': end,
                'name': name,
                'permissions': {
                    'r': mem_info.IsReadable(),
                    'w': mem_info.IsWritable(),
                    'x': mem_info.IsExecutable(),
                },
                'content_file': '',
            }
            memory_list.append(mem_info_obj)
    # 开始正式dump
    for seg_info in memory_list:
        try:
            start_addr = seg_info['start']  # type: int
            end_addr = seg_info['end']  # type: int
            region_name = seg_info['name']  # type: str
            permissions = seg_info['permissions']  # type: Dict[str, bool]

            # 跳过不可读 之后考虑下是不是能修改权限再读
            if seg_info['permissions']['r'] is False:
                logger.warning(f'Skip dump {region_name} permissions => {permissions}')
                continue

            # 超过预设大小的 跳过dump
            predicted_size = end_addr - start_addr
            if predicted_size > max_seg_size:
                logger.warning(f'Skip dump {region_name} size:0x{predicted_size:x}')
                continue

            skip_dump = False

            for rule in black_list['startswith']:
                if region_name.startswith(rule):
                    skip_dump = True
                    logger.warning(f'Skip dump {region_name} hit startswith rule:{rule}')
            if skip_dump: continue

            for rule in black_list['endswith']:
                if region_name.endswith(rule):
                    skip_dump = True
                    logger.warning(f'Skip dump {region_name} hit endswith rule:{rule}')
            if skip_dump: continue

            for rule in black_list['includes']:
                if rule in region_name:
                    skip_dump = True
                    logger.warning(f'Skip dump {region_name} hit includes rule:{rule}')
            if skip_dump: continue

            # 开始读取内存
            ts = datetime.now()
            err = lldb.SBError()
            seg_content = process.ReadMemory(start_addr, predicted_size, err)
            tm = (datetime.now() - ts).total_seconds()
            # 读取成功的才写入本地文件 并计算md5
            # 内存里面可能很多地方是0 所以压缩写入文件 减少占用
            if seg_content is None:
                logger.debug(f'Segment empty: @0x{start_addr:016x} {region_name} => {err}')
            else:
                logger.info(
                    f'Dumping @0x{start_addr:016x} {tm:.2f}s size:0x{len(seg_content):x}: {region_name} {permissions}')
                compressed_seg_content = zlib.compress(seg_content)
                md5_sum = hashlib.md5(compressed_seg_content).hexdigest() + '.bin'
                seg_info['content_file'] = md5_sum
                (dump_path / md5_sum).write_bytes(compressed_seg_content)
        except Exception as e:
            # 这里好像不会出现异常 因为前面有 SBError 处理了 不过还是保留
            logger.error(f'Exception reading segment {region_name}', exc_info=e)

    return memory_list


def archive(dump_path: Path):
    '''
    打包dump文件夹 便于提取 毕竟小文件太多不方便
    '''
    zip_path = dump_path.parent / f'{dump_path.stem}.zip'
    zipobj = zipfile.ZipFile(zip_path.as_posix(), 'w', zipfile.ZIP_STORED)
    for path, dirnames, filenames in os.walk(dump_path.as_posix()):
        # 去掉目标跟路径 替换的是 dump_path.parent 这样多一层文件夹 解压不会乱
        fpath = Path(path).as_posix().replace(dump_path.parent.as_posix(), '')
        for filename in filenames:
            zipobj.write(os.path.join(path, filename), os.path.join(fpath, filename))
    # 删除临时dump文件夹
    shutil.rmtree(dump_path.as_posix())


def dump_context(debugger: 'SBDebugger', command: str, exe_ctx: 'SBExecutionContext', result: 'SBCommandReturnObject',
                 internal_dict: dict):
    # 设置日志
    global logger
    log_tag = 'LLDBDumper'
    log_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = Path(__file__).parent / f'{log_tag}_{log_time}.log'
    logger = setup_logger(log_tag, log_path, first_call=True)

    logger.info(f'----------->start dumping<-----------')

    target = exe_ctx.GetTarget()  # type: SBTarget

    # 获取架构信息
    arch_long = dump_arch_info(target)
    logger.info(f'arch => {arch_long}')

    # 获取寄存器信息
    frame = exe_ctx.GetFrame()  # type: SBFrame
    regs = dump_regs(frame)

    # 获取内存分段信息
    sections = dump_memory_info(target)

    # 创建临时文件夹
    dump_path = Path(f'DumpContext_{log_time}').resolve()
    if dump_path.exists() is False:
        dump_path.mkdir()
    logger.info(f'dump to {dump_path.as_posix()}')

    # 保存内存分段信息
    memory_info = json.dumps(sections, ensure_ascii=False, indent=4)
    (dump_path / '_memory.json').write_text(memory_info, encoding='utf-8')
    logger.info(f'dump _memory.json end')

    # 设置过滤黑名单 符合下面条件的跳过dump
    black_list = {
        'startswith': ['/dev', '/system/fonts', '/dmabuf'],
        'endswith': ['(deleted)', '.apk', '.odex', '.vdex', '.dex', '.jar', '.art', '.oat', '.art]'],
        'includes': [],
    }
    # 设置单个内存分段dump大小上限
    max_seg_size = 64 * 1024 * 1024

    # dump内存
    process = exe_ctx.GetProcess()  # type: SBProcess
    segments = dump_memory(process, dump_path, black_list, max_seg_size)
    context = {
        'arch': arch_long,
        'regs': regs,
        'segments': segments,
    }

    # 保存内存信息
    context_config = json.dumps(context, ensure_ascii=False, indent=4)
    (dump_path / '_index.json').write_text(context_config, encoding='utf-8')
    logger.info(f'dump _index.json end')

    # 打包临时文件夹
    archive(dump_path)
    logger.info(f'archive {dump_path} end')


def helloworld(debugger: 'SBDebugger', command: str, exe_ctx: 'SBExecutionContext', result: 'SBCommandReturnObject',
               internal_dict: dict):
    print('helloWorld debugger:', debugger)
    print('helloWorld command:', command)