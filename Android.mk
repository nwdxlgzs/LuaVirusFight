LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES += $(LOCAL_PATH)/../lua
LOCAL_MODULE     := LuaVirusFightUtils
LOCAL_SRC_FILES  := LuaVirusFightUtils.c
LOCAL_STATIC_LIBRARIES := luajava

LOCAL_LDLIBS    += -llog

 LOCAL_CFLAGS += -mllvm -sobf
 LOCAL_CFLAGS += -mllvm -fla
 LOCAL_CFLAGS += -mllvm -split
 LOCAL_CFLAGS += -mllvm -sub
 LOCAL_CFLAGS += -mllvm -bcf -bcf_loop=2 -mllvm -bcf_prob=100



include $(BUILD_SHARED_LIBRARY)
