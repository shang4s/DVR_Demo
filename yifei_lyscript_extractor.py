#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
易飞工具密码数据提取器 (LyScript x32dbg 远程调试版本)
LyScript是一款专为x32/x64dbg调试器深度定制的自动化调试与逆向分析插件

功能: 远程连接x32dbg调试器，自动提取全局密钥表数据
所需: x32dbg + LyScript插件 + x32dbg Python包

安装步骤:
1. pip install x32dbg
2. 在x32dbg中加载LyScript插件
3. 运行本脚本自动提取数据
"""

import sys
import time
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from x32dbg import Config, BaseHttpClient, Debugger, Memory
    print("[✓] LyScript库已正确安装")
except ImportError:
    print("[✗] 错误: x32dbg库未安装")
    print("请执行: pip install x32dbg")
    sys.exit(1)


class YiFeiExtractor:
    """易飞工具密钥数据提取器"""
    
    # 关键地址定义
    TARGET_TABLE_1 = 0x00511B30  # 16字节主密钥表
    TARGET_TABLE_2 = 0x00511B8A  # 96字节轮密钥表
    DECRYPT_FUNC_1 = 0x00509754  # 第一种解密函数
    DECRYPT_FUNC_2 = 0x0050A7E0  # 第二种解密函数
    ROUND_FUNC = 0x00509E48      # 轮函数
    
    def __init__(self, server_addr: str = "127.0.0.1", server_port: int = 8000):
        """
        初始化提取器
        
        Args:
            server_addr: x32dbg LyScript服务地址
            server_port: x32dbg LyScript服务端口
        """
        self.config = Config(address=server_addr, port=server_port)
        self.http_client = None
        self.debugger = None
        self.memory = None
        self.data = {}
        
    def connect(self) -> bool:
        """
        连接到x32dbg远程调试器
        
        Returns:
            bool: 连接成功返回True
        """
        try:
            print(f"[*] 尝试连接到 {self.config.address}:{self.config.address_port}...")
            
            # 检查服务器可用性
            is_available = self.config.is_server_available()
            if not is_available:
                print("[✗] 错误: x32dbg服务不可用")
                print("请确保:")
                print("  1. x32dbg已启动")
                print("  2. LyScript插件已加载")
                print("  3. 服务地址和端口正确")
                return False
            
            # 初始化HTTP客户端
            self.http_client = BaseHttpClient(self.config, debug=False)
            print("[✓] HTTP客户端初始化成功")
            
            # 初始化调试器接口
            self.debugger = Debugger(self.http_client)
            print("[✓] 调试器接口初始化成功")
            
            # 初始化内存接口
            self.memory = Memory(self.http_client)
            print("[✓] 内存接口初始化成功")
            
            # 验证调试器活跃状态
            is_active = self.debugger.IsDebugger()
            if not is_active.get("is_debugger"):
                print("[✗] 错误: 调试器未激活")
                return False
            
            print("[✓] 调试器已激活")
            return True
            
        except Exception as e:
            print(f"[✗] 连接失败: {str(e)}")
            return False
    
    def read_memory_raw(self, address: int, size: int) -> Optional[bytes]:
        """
        从指定地址读取原始内存数据
        
        Args:
            address: 内存地址
            size: 读取字节数
            
        Returns:
            bytes: 读取的数据，失败返回None
        """
        try:
            # 转换为十六进制地址字符串
            addr_hex = hex(address)
            
            # 调用LyScript内存读取接口
            result = self.memory.ReadMemory(addr_hex, size)
            
            if result.get("status") == "success":
                hex_data = result.get("memory_hex", "")
                # 将十六进制字符串转换为字节数组
                byte_data = bytes.fromhex(hex_data.replace(" ", ""))
                return byte_data
            else:
                print(f"[✗] 读取内存失败 (地址: {addr_hex})")
                return None
                
        except Exception as e:
            print(f"[✗] 内存读取异常: {str(e)}")
            return None
    
    def extract_table_1(self) -> bool:
        """
        提取第一个密钥表 (0x00511B30, 16字节)
        
        Returns:
            bool: 成功返回True
        """
        try:
            print(f"\n[*] 提取密钥表1 (地址: 0x{self.TARGET_TABLE_1:08X}, 大小: 16字节)...")
            
            data = self.read_memory_raw(self.TARGET_TABLE_1, 16)
            if data is None:
                return False
            
            # 转换为十六进制字符串
            hex_str = " ".join([f"{b:02X}" for b in data])
            print(f"[✓] 表1数据: {hex_str}")
            
            self.data["table_1"] = {
                "address": f"0x{self.TARGET_TABLE_1:08X}",
                "size": 16,
                "hex": hex_str,
                "raw": list(data)
            }
            
            return True
            
        except Exception as e:
            print(f"[✗] 表1提取失败: {str(e)}")
            return False
    
    def extract_table_2(self) -> bool:
        """
        提取第二个密钥表 (0x00511B8A, 96字节)
        轮密钥表结构: 16轮 × 6字节 = 96字节
        
        Returns:
            bool: 成功返回True
        """
        try:
            print(f"\n[*] 提取密钥表2 (地址: 0x{self.TARGET_TABLE_2:08X}, 大小: 96字节, 16轮)...")
            
            data = self.read_memory_raw(self.TARGET_TABLE_2, 96)
            if data is None:
                return False
            
            # 按轮分组显示 (16轮 × 6字节)
            hex_str = " ".join([f"{b:02X}" for b in data])
            print(f"[✓] 表2数据: {hex_str}")
            
            # 解析轮结构
            rounds = []
            for round_idx in range(16):
                round_data = data[round_idx * 6:(round_idx + 1) * 6]
                round_hex = " ".join([f"{b:02X}" for b in round_data])
                rounds.append({
                    "round": round_idx,
                    "hex": round_hex,
                    "raw": list(round_data)
                })
                print(f"  [轮{round_idx:2d}] {round_hex}")
            
            self.data["table_2"] = {
                "address": f"0x{self.TARGET_TABLE_2:08X}",
                "size": 96,
                "total_rounds": 16,
                "bytes_per_round": 6,
                "hex": hex_str,
                "raw": list(data),
                "rounds": rounds
            }
            
            return True
            
        except Exception as e:
            print(f"[✗] 表2提取失败: {str(e)}")
            return False
    
    def extract_function_info(self) -> bool:
        """
        提取关键函数的信息
        
        Returns:
            bool: 成功返回True
        """
        try:
            print(f"\n[*] 提取关键函数信息...")
            
            functions = {
                "decrypt_password_method_1": self.DECRYPT_FUNC_1,
                "decrypt_password_method_2": self.DECRYPT_FUNC_2,
                "round_function": self.ROUND_FUNC
            }
            
            func_info = {}
            for func_name, func_addr in functions.items():
                # 读取函数入口处的指令
                instr = self.debugger.DisasmOneCode(hex(func_addr))
                
                if instr.get("status") == "success":
                    func_info[func_name] = {
                        "address": hex(func_addr),
                        "instruction": instr.get("instruction", ""),
                        "size": instr.get("instruction_size", 0)
                    }
                    print(f"  [✓] {func_name}: 0x{func_addr:08X}")
            
            self.data["functions"] = func_info
            return True
            
        except Exception as e:
            print(f"[!] 函数信息提取失败 (非致命): {str(e)}")
            return False
    
    def verify_data(self) -> bool:
        """
        验证提取的数据完整性
        
        Returns:
            bool: 数据有效返回True
        """
        print(f"\n[*] 验证提取的数据...")
        
        # 检查表1
        if "table_1" not in self.data:
            print("[✗] 表1数据缺失")
            return False
        
        table1 = self.data["table_1"]
        if len(table1["raw"]) != 16:
            print(f"[✗] 表1大小错误: 预期16字节, 得到{len(table1['raw'])}字节")
            return False
        
        print(f"[✓] 表1数据有效 (16字节)")
        
        # 检查表2
        if "table_2" not in self.data:
            print("[✗] 表2数据缺失")
            return False
        
        table2 = self.data["table_2"]
        if len(table2["raw"]) != 96:
            print(f"[✗] 表2大小错误: 预期96字节, 得到{len(table2['raw'])}字节")
            return False
        
        print(f"[✓] 表2数据有效 (96字节 = 16轮 × 6字节)")
        
        return True
    
    def save_to_file(self, filename: str = "yifei_keys.json") -> bool:
        """
        将提取的数据保存到JSON文件
        
        Args:
            filename: 输出文件名
            
        Returns:
            bool: 保存成功返回True
        """
        try:
            output_path = Path(filename)
            
            # 添加元数据
            self.data["metadata"] = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "source": "易飞工具.exe (LyScript远程提取)",
                "tool": "LyScript x32dbg Remote Debugger",
                "platform": "x86",
                "description": "从易飞工具程序运行时内存中提取的加密密钥表"
            }
            
            # 保存为JSON
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            
            print(f"\n[✓] 数据已保存到: {output_path.absolute()}")
            return True
            
        except Exception as e:
            print(f"[✗] 保存文件失败: {str(e)}")
            return False
    
    def generate_c_code(self, filename: str = "yifei_keys.h") -> bool:
        """
        生成C语言头文件，可直接用于解密实现
        
        Args:
            filename: 输出文件名
            
        Returns:
            bool: 生成成功返回True
        """
        try:
            output_path = Path(filename)
            
            # 获取表数据
            table1 = self.data.get("table_1", {}).get("raw", [])
            table2 = self.data.get("table_2", {}).get("raw", [])
            
            # 生成C代码
            c_code = """/*
 * 易飞工具密钥表数据
 * 自动从运行时内存提取 (LyScript x32dbg)
 * 生成时间: {timestamp}
 */

#ifndef YIFEI_KEYS_H
#define YIFEI_KEYS_H

#include <stdint.h>

/* 表1: 主密钥表 (16字节) */
/* 地址: 0x00511B30 */
/* 用途: 第一种解密算法的基础密钥表 */
static const uint8_t gvar_00511B30[16] = {{
{table1_init}
}};

/* 表2: 轮密钥表 (96字节 = 16轮 × 6字节) */
/* 地址: 0x00511B8A */
/* 用途: 第二种解密算法的轮密钥表 */
static const uint8_t gvar_00511B8A[96] = {{
{table2_init}
}};

/* 轮密钥表结构 */
typedef struct {{
    uint8_t round_key[6];  /* 每轮6字节 */
}} RoundKey_t;

/* 轮密钥表访问助手 */
#define GET_ROUND_KEY(round_num) (&gvar_00511B8A[(round_num) * 6])

#endif /* YIFEI_KEYS_H */
""".format(
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                table1_init=", ".join([f"0x{b:02X}" for b in table1]),
                table2_init=", ".join([f"0x{b:02X}" for b in table2])
            )
            
            # 保存C头文件
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(c_code)
            
            print(f"[✓] C头文件已生成: {output_path.absolute()}")
            return True
            
        except Exception as e:
            print(f"[✗] 生成C代码失败: {str(e)}")
            return False
    
    def display_summary(self):
        """显示提取总结"""
        print("\n" + "="*70)
        print("                    提取总结")
        print("="*70)
        
        if "table_1" in self.data:
            table1 = self.data["table_1"]
            print(f"\n[表1] 主密钥表")
            print(f"  地址:  {table1['address']}")
            print(f"  大小:  {table1['size']} 字节")
            print(f"  数据:  {table1['hex']}")
        
        if "table_2" in self.data:
            table2 = self.data["table_2"]
            print(f"\n[表2] 轮密钥表")
            print(f"  地址:  {table2['address']}")
            print(f"  大小:  {table2['size']} 字节 ({table2['total_rounds']}轮 × {table2['bytes_per_round']}字节)")
            print(f"  首轮:  {table2['rounds'][0]['hex']}")
            print(f"  末轮:  {table2['rounds'][-1]['hex']}")
        
        print("\n[✓] 提取完成!")
        print("="*70)
    
    def run(self) -> bool:
        """
        执行完整的提取流程
        
        Returns:
            bool: 全部成功返回True
        """
        print("="*70)
        print("      易飞工具密钥数据提取器 (LyScript x32dbg 远程版)")
        print("="*70)
        
        # 连接调试器
        if not self.connect():
            return False
        
        time.sleep(0.5)
        
        # 提取数据
        success = True
        success = self.extract_table_1() and success
        success = self.extract_table_2() and success
        self.extract_function_info()  # 非必需
        
        if not success:
            print("\n[✗] 数据提取失败!")
            return False
        
        # 验证数据
        if not self.verify_data():
            print("\n[✗] 数据验证失败!")
            return False
        
        # 保存数据
        self.save_to_file("yifei_keys.json")
        self.generate_c_code("yifei_keys.h")
        
        # 显示总结
        self.display_summary()
        
        return True


def main():
    """主函数"""
    
    # 解析命令行参数
    server_addr = "127.0.0.1"
    server_port = 8000
    
    if len(sys.argv) > 1:
        server_addr = sys.argv[1]
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])
    
    # 创建提取器并运行
    extractor = YiFeiExtractor(server_addr, server_port)
    success = extractor.run()
    
    # 返回状态码
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
