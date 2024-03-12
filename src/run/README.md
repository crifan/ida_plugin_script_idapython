# 运行IDA脚本插件

* 运行IDA脚本插件
  * 最典型方式：加载脚本文件=`Script file`
    * 步骤
      * `IDA`->`File`->`Script file` ->选择对应IDA的Python脚本文件-》即可运行
    * 图
      * Mac
        * ![ida_script_file_mac](../assets/img/ida_script_file_mac.png)
        * ![script_file_choose_py](../assets/img/script_file_choose_py.png)
      * Win
        * ![ida_script_file_win](../assets/img/ida_script_file_win.jpg)
  * 其他方式
    * `IDAPython Interpreter`=`IDAPython交互式命令行解析器`
      * 主要用途：临时写点Python脚本代码测试
      * 界面
        * ![ida_idapython_interpreter_win](../assets/img/ida_idapython_interpreter_win.jpg)
    * `Script Command`
      * 步骤
        * `IDA`->`File`->`Script Command` ->自己输入要运行的Python脚本
      * 图
        * Mac
          * ![ida_script_command_mac](../assets/img/ida_script_command_mac.png)
          * ![script_command_py_code](../assets/img/script_command_py_code.png)
