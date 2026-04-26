import ncccutil from "#runtime/nccc/ncccutil.mjs";
//import nativeresources from "#build/nativeresources.mjs";

//const yfrmdll0 = ncccutil.opennccc(nativeresources.yfrm); /* Both yfrm and cwgl */
const cwgldll0 = ncccutil.opennccc("./_nccc/libnccc_cwgl.so");
const cwglroot = ncccutil.resolvenccc(cwgldll0, "cwgl");
const cwglobj = ncccutil.loadlib(cwglroot);
const CWGL = {};

// Inject NCCC version of procedures
for(const idx in cwglobj.exports){
    CWGL[idx] = cwglobj.exports[idx].proc;
}

export default CWGL;
