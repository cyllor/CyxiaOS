# 原始验证日志

此目录保存本轮实际命令输出的gzip压缩副本；解压字节与verification.json的SHA-256对应，压缩不改变日志内容。`gzip -dc <文件.log.gz>`可查看。

名称含red、green不保证结果为红/绿：请以实际退出码和日志终态为准。例如loader-portable-green.log仍有4个Linux cp错误，最终通过记录为loader-portable-final.log。原始全tools失败日志必须保留，后续定向通过不能代替未重跑的全套。

Finding及x86首轮红阶段只保留于执行工具输出，未伪造为原始日志文件；verification.json明确区分这一来源。
