dofile=nil;loadfile=nil;--dofile/loasfile必须死，否则运行lua就够你喝一壶了
require "import"
import "LuaVirusFightUtils"--辅助工具(自己写libloader加载so)
import "VirusDatabase"--病毒数据库
local filepath=""
local filefunc=LuaVirusFightUtils.safeloadfile(filepath)
print(dump(VirusDatabase(filefunc)))--评估表
