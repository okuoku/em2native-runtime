function ncccutil(PortNative){
    const corelib = PortNative.nccc.corelib;
    const node_nccc = PortNative.nccc;

    const util_rawcall_addr = corelib.util_rawcall;
    const util_peek_u64_addr = corelib.util_peek_u64;
    const util_poke_u64_addr = corelib.util_poke_u64;
    const util_peek_u32_addr = corelib.util_peek_u32;
    const util_peek_u8_addr = corelib.util_peek_u8;
    const util_poke_u32_addr = corelib.util_poke_u32;
    const util_peek_ptr_addr = corelib.util_peek_ptr;
    const util_malloc_addr = corelib.util_malloc;
    const util_free_addr = corelib.util_free;
    const util_ptraddr_addr = corelib.util_ptraddr;

    const util_rawcall = node_nccc.make_nccc_call("rawcall",
                                                  0, util_rawcall_addr,
                                                  "lll", "");
    const util_malloc = node_nccc.make_nccc_call("malloc",
                                                 0, util_malloc_addr,
                                                 "l", "l");
    const util_free = node_nccc.make_nccc_call("free",
                                               0, util_free_addr,
                                               "l", "");
    const util_peek_u64 = node_nccc.make_nccc_call("peek_u64",
                                                   0, util_peek_u64_addr,
                                                   "p", "l");
    const util_peek_u32 = node_nccc.make_nccc_call("peek_u32",
                                                   0, util_peek_u32_addr,
                                                   "p", "l");
    const util_peek_u8 = node_nccc.make_nccc_call("peek_u8",
                                                  0, util_peek_u8_addr,
                                                  "p", "l");
    const util_peek_f64 = node_nccc.make_nccc_call("peek_f64", // reinterpret
                                                   0, util_peek_u64_addr,
                                                   "p", "d");
    const util_peek_f32 = node_nccc.make_nccc_call("peek_f32", // reinterpret
                                                   0, util_peek_u32_addr,
                                                   "p", "f");
    const util_peek_ptr = node_nccc.make_nccc_call("peek_ptr", // trunc
                                                   0, util_peek_ptr_addr,
                                                   "p", "l");
    const util_poke_u64 = node_nccc.make_nccc_call("poke_u64",
                                                   0, util_poke_u64_addr,
                                                   "pl", "");
    const util_poke_f64 = node_nccc.make_nccc_call("poke_f64", // reinterpret
                                                   0, util_poke_u64_addr,
                                                   "pd", "");
    const util_poke_f32 = node_nccc.make_nccc_call("poke_f32", // reinterpret
                                                   0, util_poke_u32_addr,
                                                   "pf", "");
    const util_ptraddr = node_nccc.make_nccc_call("ptraddr",
                                                  0, util_ptraddr_addr,
                                                  "p","l");
    const util_addrptr = node_nccc.make_nccc_call("addrptr",
                                                  0, util_ptraddr_addr,
                                                  "l","p");

    const dlfcn_open = node_nccc.make_nccc_call("dlfcn_open",
                                                0, corelib.dlfcn_open,
                                                "p", "lp");
    const dlfcn_get = node_nccc.make_nccc_call("dlfcn_get",
                                               0, corelib.dlfcn_get,
                                               "pp", "lp");

    function dlopen(path){ // => handle
        const r = dlfcn_open(path);
        if(r[0] != 0){
            throw "dlopen error";
        }
        console.log("dlopen",path,r);
        return r[1];
    }

    function dlsym(handle,name){ // => ptr
        const r = dlfcn_get(handle, name);
        if(r[0] != 0){
            throw "dlsym error";
        }
        console.log("dlsym",handle,name,r);
        return r[1];
    }

    function fetchbyte(addr){
        if(addr == 0){
            throw "Invalid address";
        }
        const v = util_peek_u8(addr);
        return v;
    }

    function fetchcstring(addr, limit){
        let acc = [];
        let c = 0;
        let cur = addr;
        let idx = 0;
        while(1){
            c = fetchbyte(cur);
            if(c == 0){
                break;
            }
            if(idx == limit){
                break;
            }
            acc.push(c);
            cur++;
            idx++;
        }
        const str = String.fromCharCode.apply(null, acc);
        return str;
    }

    function do_rawcall(addr, ina, outcount){
        const out = [];
        const inbuf = util_malloc(8 * ina.length);
        const outbuf = util_malloc(8 * outcount);
        let i = 0;
        for(i=0;i!=ina.length;i++){
            util_poke_u64(inbuf + i*8, ina[i]);
        }
        util_rawcall(addr, inbuf, outbuf);
        for(i=0;i!=outcount;i++){
            out.push(util_peek_u64(outbuf + i*8));
        }
        util_free(inbuf);
        util_free(outbuf);
        return out;
    }

    function nccctypechar(nr){
        switch(nr){
            case 0: /* u32 */
                return "I";
            case 1: /* u64 */
                return "L";
            case 2: /* f32 */
                return "f";
            case 3: /* f64 */
                return "d";
            case 4: /* s32 */
                return "i";
            case 5: /* s64 */
                return "l";
            case 6: /* ptr */
                return "p";
            case 7: /* uptr */
                return "X";
            case 8: /* sptr */
                return "x";
            case 9: /* u8 */
                return "B";
            case 10: /* u16 */
                return "H";
            case 11: /* s8 */
                return "b";
            case 12: /* s16 */
                return "h";
            default:
                throw "Unknown";
        }
    }

    function nccctypes2string(types){
        return types.reduce((acc, e) => acc + nccctypechar(e), "");
    }

    function opennccc(path){
        const dllfile = dlopen(path);
        return dllfile;
    }

    function resolvenccc(nccc, modname){
        const rootaddr = dlsym(nccc, "lib_" + modname + "_dispatch_ncccv0");
        return rootaddr;
    }

    function loadlib(rootaddr){ // => {exports: ...}
        function library_info(){
            const out = do_rawcall(rootaddr, [1], 6);
            const r = {
                name0: fetchcstring(out[0]),
                name1: out[1] == 0 ? false : fetchcstring(out[1]),
                max_exports: out[2],
                max_imports: out[3],
                max_variables: out[4],
                max_stubs: out[5]
            };
            return r;
        }
        function get_export(exportid){
            // library_export_info
            const out = do_rawcall(rootaddr, [2, exportid], 8);
            if(out[0] != 0){
                throw "Invalid res";
            }
            const info = {
                objid: out[1],
                name: fetchcstring(out[2]),
                stubtype: out[3],
                addr0: out[4],
                addr1: out[5],
                incount: out[6],
                outcount: out[7]
            };
            // library_arg_info
            const arga = do_rawcall(rootaddr, [6, info.objid],
                                    info.incount + info.outcount + 3);
            if(arga[0] != 0){
                throw "Invalid res";
            }
            const inc = arga[1]; // Use return value
            const outc = arga[2]; // Use return value
            const parama = nccctypes2string(arga.slice(3,3+inc));
            const resulta = nccctypes2string(arga.slice(3+inc,3+inc+outc));
            console.log("Generating",info.name,info.addr1,parama,resulta);
            info.proc = node_nccc.make_nccc_call(info.name, info.addr0, info.addr1,
                                                 parama, resulta);
            return info;
        }

        const lib = {exports: {}};
        const libinfo = library_info();
        console.log("Library", libinfo);
        for(let expi = 0; expi != libinfo.max_exports; expi++){
            const exp = get_export(expi);
            console.log("Export", exp);
            lib.exports[exp.name] = exp;
        }

        return lib;
    }

    function opendll_raw(path, rootsym){ // => addr
        const dllfile = dlopen(path);
        const rootaddr = dlsym(dllfile, rootsym); 
        return rootaddr;
    }

    function opendll_null(path){ // => something
        const dllfile = dlopen(path);
        return dllfile;
    }

    function gencb(the_cb){
        let myctx = null;
        function freecb(arg0,ptr){
            if(ptr === false){
                myctx = arg0;
            }else{
                the_cb(ptr);
                node_nccc.destroy_cb_ctx(myctx);
            }
        }
        return freecb;
    }

    function wrapptr(ptr, freecb){ // => ptr
        const cb = gencb(freecb);
        const cba = node_nccc.make_nccc_cb(cb, "pp", "");
        cb(cba[1], false);
        return node_nccc.wrap_pointer(ptr, cba[0], cba[1], 999);
    }

    // FIXME: 64bits version
    function ptrbuf(){
        return new Uint32Array(2);
    }
    function fetchptrbuf(buf){
        const v = util_peek_ptr(buf);
        return util_addrptr(v);
    }


    return {
        opennccc: opennccc,
        resolvenccc: resolvenccc,
        loadlib: loadlib,
        opendll_raw: opendll_raw,
        opendll_null: opendll_null,
        fetchcstring: fetchcstring,
        node_nccc: node_nccc,
        rawcall: util_rawcall,
        malloc: util_malloc,
        free: util_free,
        ptraddr: util_ptraddr,
        addrptr: util_addrptr,
        peek_u64: util_peek_u64,
        peek_u32: util_peek_u32,
        peek_u8: util_peek_u8,
        peek_f64: util_peek_f64,
        peek_f32: util_peek_f32,
        peek_ptr: util_peek_ptr,
        poke_u64: util_poke_u64,
        poke_f64: util_poke_f64,
        poke_f32: util_poke_f32,
        wrapptr: wrapptr,
        ptrbuf: ptrbuf,
        fetchptrbuf: fetchptrbuf,
        corelib: corelib
    };
}

export default ncccutil;
