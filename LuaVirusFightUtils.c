#ifndef HIDE_SYMBOL
#define HIDE_SYMBOL __attribute__((visibility("hidden")))
#endif
#include "android/log.h"
#define LOG_TAG "[LuaVirusFightUtils]"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "lua.h"
#include "lapi.h"
#include "lauxlib.h"
#include "lobject.h"
#include "lstate.h"
#include "lfunc.h"
#include "lopcodes.h"
#include "lualib.h"


const TValue luaO_nilobject_ = {NILCONSTANT};

static StkId _index2addr(lua_State *L, int idx) {
    CallInfo *ci = L->ci;
    if (idx > 0) {
        TValue *o = ci->func + idx;
        api_check(L, idx <= ci->top - (ci->func + 1), "不可接受的索引");
        if (o >= L->top) return cast(TValue *, luaO_nilobject);
        else return o;
    } else if (!((idx) <= LUA_REGISTRYINDEX)) {
        api_check(L, idx != 0 && -idx <= L->top - (ci->func + 1), "无效的索引");
        return L->top + idx;
    } else if (idx == LUA_REGISTRYINDEX) {
        return &G(L)->l_registry;
    } else {
        idx = LUA_REGISTRYINDEX - idx;
        api_check(L, idx <= MAXUPVAL + 1, "上值(upvalue)索引太大了");
        if (ttislcf(ci->func))
            return cast(TValue *, luaO_nilobject);
        else {
            CClosure *func = clCvalue(ci->func);
            return (idx <= func->nupvalues) ? &func->upvalue[idx - 1] : cast(TValue *,
                                                                             luaO_nilobject);
        }
    }
}

static void _luaL_setfuncs(lua_State *L, const luaL_Reg *l, int nup) {
    luaL_checkstack(L, nup + 1, "太多上值(upvalues)");
    for (; l->name != NULL; l++) {
        int i;
        lua_pushstring(L, l->name);
        for (i = 0; i < nup; i++)
            lua_pushvalue(L, -(nup + 1));
        lua_pushcclosure(L, l->func, nup);
        lua_settable(L, -(nup + 3));
    }
    lua_pop(L, nup);
}

static void watchConsts(lua_State *L, Proto *f) {
    int i;
    for (i = 0; i < f->sizek; i++) {
        StkId o = &f->k[i];
        if(ttisnil(o))continue;
        setobjs2s(L, L->top, o);
        L->top++;
        lua_pushboolean(L, 1);
        lua_settable(L, -3);
    }
    for (i = 0; i < f->sizep; i++) {
        watchConsts(L, f->p[i]);
    }
}

static int Native_getConsts(lua_State *L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    StkId func = _index2addr(L, 1);
    if (isLfunction(func)) {
        lua_newtable(L);
        lua_newtable(L);
        Proto *f = getproto(func);
        watchConsts(L, f);
        //进行去除（取键加进实际表）
        int idx = 0;
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            lua_pop(L, 1);//弹走value
            lua_pushvalue(L, -1);//再压入一个key(seti会消耗key，会导致遍历终止，所以拎出来一个用于加进表)
            lua_seti(L, -4, ++idx);//加进实际表
        }
        return 2;
    } else {
        return luaL_error(L, "参数必须是Lua函数");
    }
}
static int Native_safeloadfile(lua_State *L) {
    const char *filename = luaL_checkstring(L, 1);
    int status = luaL_loadfile(L, filename);
    if (status == LUA_OK) {
        StkId func = _index2addr(L, -1);
        Proto *f = getproto(func);
        f->sizecode = 1;
        f->code= realloc(f->code, sizeof(Instruction)*f->sizecode);
        f->code[0] = CREATE_ABC(OP_RETURN, 0, 1, 0);
        return 1;
    }
    return 0;
}
int luaopen_LuaVirusFightUtils(lua_State *L) {
    luaL_Reg l[] = {
            {"getConsts", Native_getConsts},
            {"safeloadfile", Native_safeloadfile},
            {NULL, NULL}
    };
    lua_newtable(L);
    _luaL_setfuncs(L, l, 0);
    return 1;
}
