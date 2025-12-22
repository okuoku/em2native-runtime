/* Copied from https://github.com/okuoku/cwgl-proto/blob/e34dffe06ac23a9797dd9ecd601433c44ab79cdd/jstestapp/port-std.js */
import fs from "fs";
import crypto from "crypto";
import perf_hooks from "perf_hooks";

export default {
    performance_now: function(){
        return perf_hooks.performance.now()
    },
    fs_readFileSync: fs.readFileSync,
    crypto_randomFillSync: crypto.randomFillSync,
};
