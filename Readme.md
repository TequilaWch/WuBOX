# WuBOX: A Syscall Tracer Based on eBPF Tech

## 0. 声明
南开大学18级本科生[吴昌昊](https://caslone.cn/)的毕业设计 基于eBPF实现的Linux系统调用过滤器。(2022)

**仅供学习交流 未经许可不得私自盗用**

## 1. 使用环境

- ubuntu 20.04
- clang 10.0.0-4ubuntu1 
- llvm 1:10.0-50~exp1
- cmake (>=3.1), gcc (>=4.7), flex, bison
- <font color=#ff0000>必须运行在sudo下</font>


## 2. 程序架构
- main.py 程序的入口，万物的起源。接收输入并切换模式。
- systrace.py 当然是trace syscall
- apptrace.py 跟踪特定app行为

## 3. 开发预期
- [ ] 增加用户态与内核态模式
- [x] 增加入口追踪与返回追踪
- [ ] 增加分析能力
- [x] 增加次数控制
- [ ] more...


## 4. 如何编译
首先需要 pyinstaller,可以通过 `sudo pip3 install pyinstaller` 进行安装

在`code`目录下, 输入`pyinstaller -F wubox.py -n wubox --distpath .`

成功打包后即可在`\code`下找到`wubox`可执行程序
