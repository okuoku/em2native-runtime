import E from "./glenums.mjs";
import getenumtype from "./getenumtype.mjs";
import ncccutil from "#runtime/nccc/ncccutil.mjs";
import CWGL from "./cwgl.mjs";

const NULL = 0;

function readcstr(buf){
    const addr = ncccutil.ptraddr(buf);
    return ncccutil.fetchcstring(addr);
}

function wrapPointer(obj, relcb){
    return ncccutil.wrapptr(ncccutil.ptraddr(obj), relcb);
}

function ptralloc(){
    return ncccutil.malloc(8);
}
function ptrfree(addr){
    return ncccutil.free(addr);
}
function ptrref(addr){
    // FIXME: Endian??
    return ncccutil.peek_ptr(addr);
}

function freectx(ptr){
    // FIXME: Implement context freeing
    console.log("Leak!", ptr);
}

function consumestring(s){ // => string
    // FIXME: On Duktape, Uint8Array freed during readcstr...?
    const ssiz = CWGL.cwgl_string_size(ctx, s);
    if(ssiz == 0){
        return ""; // Short circuit
    }
    //const buf = new Uint8Array(ssiz+1);
    const buf = ncccutil.malloc(ssiz+1);
    CWGL.cwgl_string_read(ctx, s, buf, ssiz+1);
    CWGL.cwgl_string_release(ctx, s);
    //buf[ssiz] = 0;
    //return readcstr(buf);
    const r = ncccutil.fetchcstring(buf, ssiz);
    ncccutil.free(buf);
    return r;
}

function objptr(obj){
    if(obj){
        return obj.ptr
    }else{
        return NULL;
    }
}

function GL(ctx0, w, h, attr){
    /* Bindings */
    let currentFramebuffer = null;
    let currentRenderbuffer = null;
    let currentTexture2D = null;
    let currentTextureCubeMap = null
    let currentArrayBuffer = null;
    let currentElementArrayBuffer = null;
    let currentProgram = null;

    /* trackbinding */
    function trackbinding_Framebuffer(fb){
        currentFramebuffer = fb;
    }
    function trackbinding_Renderbuffer(rb){
        currentRenderbuffer = rb;
    }
    function trackbinding_texture(target, texture){
        switch(target){
            case E.TEXTURE_2D:
                currentTexture2D = texture;
                break;
            case E.TEXTURE_CUBE_MAP:
                currentTextureCubeMap = texture;
                break;
            default:
                throw "huh?";
        }
    }
    function trackbinding_buffer(target, buffer){
        switch(target){
            case E.ARRAY_BUFFER:
                currentArrayBuffer = buffer;
                break;
            case E.ELEMENT_ARRAY_BUFFER:
                currentElementArrayBuffer = buffer;
                break;
            default:
                throw "huh?";
        }
    }
    function trackbinding_program(program){
        currentProgram = program;
    }

    function texfree(ptr){
        CWGL.cwgl_Texture_release(ctx, ptr);
    }
    function framebufferfree(ptr){
        CWGL.cwgl_Framebuffer_release(ctx, ptr);
    }
    function bufferfree(ptr){
        CWGL.cwgl_Buffer_release(ctx, ptr);
    }
    function renderbufferfree(ptr){
        CWGL.cwgl_Renderbuffer_release(ctx, ptr);
    }
    function shaderfree(ptr){
        CWGL.cwgl_Shader_release(ctx, ptr);
    }
    function programfree(ptr){
        CWGL.cwgl_Program_release(ctx, ptr);
    }
    function uniformlocationfree(ptr){
        CWGL.cwgl_UniformLocation_release(ctx, ptr);
    }

    const ctx = wrapPointer(ctx0, freectx);
    // const evtbuf = new Int32Array(128);
    const R = {
        // 5.14.1 Attributes
        /// canvas (set by client)
        drawingBufferWidth: w,
        drawingBufferHeight: h,

        // 5.14.2 Getting information about the context
        // FIXME: Fill actual attributes
        /* WebGLHandlesContextLoss */
        getContextAttributes: function(){
            return {};
        },

        // 5.14.3 Setting and getting state
        activeTexture: function(texture){
            CWGL.cwgl_activeTexture(ctx, texture);
        },
        blendColor: function(red, green, blue, alpha){
            CWGL.cwgl_blendColor(ctx, red, green, blue, alpha);
        },
        blendEquation: function(mode){
            CWGL.cwgl_blendEquation(ctx, mode);
        },
        blendEquationSeparate: function(modeRGB, modeAlpha){
            CWGL.cwgl_blendEquationSeparate(ctx, modeRGB, modeAlpha);
        },
        blendFunc: function(sfactor, dfactor){
            CWGL.cwgl_blendFunc(ctx, sfactor, dfactor);
        },
        blendFuncSeparate: function(srcRGB, dstRGB, srcAlpha, dstAlpha){
            CWGL.cwgl_blendFuncSeparate(ctx, srcRGB, dstRGB, srcAlpha, dstAlpha);
        },
        clearColor: function(red, green, blue, alpha){
            CWGL.cwgl_clearColor(ctx, red, green, blue, alpha);
        },
        clearDepth: function(depth){
            CWGL.cwgl_clearDepth(ctx, depth);
        },
        clearStencil: function(s){
            CWGL.cwgl_clearStencil(ctx, s);
        },
        colorMask: function(red, green, blue, alpha){
            const r = red ? 1 : 0;
            const g = green ? 1 : 0;
            const b = blue ? 1 : 0;
            const a = alpha ? 1 : 0;
            CWGL.cwgl_colorMask(ctx, r, g, b, a);
        },
        cullFace: function(mode){
            CWGL.cwgl_cullFace(ctx, mode);
        },
        depthFunc: function(func){
            CWGL.cwgl_depthFunc(ctx, func);
        },
        depthMask: function(flag){
            const f = flag ? 1 : 0;
            CWGL.cwgl_depthMask(ctx, f);
        },
        depthRange: function(zNear, zFar){
            CWGL.cwgl_depthRange(ctx, zNear, zFar);
        },
        disable: function(cap){
            CWGL.cwgl_disable(ctx, cap);
        },
        enable: function(cap){
            CWGL.cwgl_enable(ctx, cap);
        },
        frontFace: function(mode){
            CWGL.cwgl_frontFace(ctx, mode);
        },
        getParameter: function(pname){
            //console.log("getParam", pname);
            switch(pname){
                case E.COMPRESSED_TEXTURE_FORMATS:
                    return [];
                case E.TEXTURE_BINDING_2D:
                    return currentTexture2D;
                case E.TEXTURE_BINDING_CUBE_MAP:
                    return currentTextureCubeMap;
                case E.ARRAY_BUFFER_BINDING:
                    return currentArrayBuffer;
                case E.FRAMEBUFFER_BINDING:
                    return currentFramebuffer;
                case E.RENDERBUFFER_BINDING:
                    return currentRenderbuffer;
                case E.ELEMENT_ARRAY_BUFFER_BINDING:
                    return currentElementArrayBuffer;
                case E.CURRENT_PROGRAM:
                    return currentProgram;
                default:
                    break;
            }
            if(pname == E.COMPRESSED_TEXTURE_FORMATS){
                // FIXME: Implement compressed texture
                return [];
            }
            const type = getenumtype(pname);
            switch(type){
                case "int":
                    {
                        let box = new Int32Array(1);
                        const r = CWGL.cwgl_getParameter_i1(ctx, pname, box);
                        if(r == 0){
                            return box[0];
                        } else {
                            return null;
                        }
                    }
                    break;
                case "bool":
                    {
                        let box = new Int32Array(1);
                        const r = CWGL.cwgl_getParameter_b1(ctx, pname, box);
                        if(r == 0){
                            return box[0] == 0 ? false : true;
                        } else {
                            return null;
                        }
                    }
                    break;
                case "b4":
                    {
                        function fold(x){ return x[0] == 0 ? false : true; }
                        let b0 = new Int32Array(1);
                        let b1 = new Int32Array(1);
                        let b2 = new Int32Array(1);
                        let b3 = new Int32Array(1);
                        const r = CWGL.cwgl_getParameter_b4(ctx, pname, b0, b1, b2, b3);
                        if(r == 0){
                            return [fold(b0), fold(b1), fold(b2), fold(b3)];
                        } else {
                            return null;
                        }
                    }
                    break;
                case "i2":
                    {
                        let i0 = new Int32Array(1);
                        let i1 = new Int32Array(1);
                        const r = CWGL.cwgl_getParameter_i2(ctx, pname, i0, i1);
                        if(r == 0){
                            //Duktape does not have .of ..?
                            //return Int32Array.of(i0[0], i1[0]);
                            const x = new Int32Array(2);
                            x[0] = i0[0];
                            x[1] = i1[0];
                            return x;
                        }else{
                            return null;
                        }
                    }
                    break;
                case "i4":
                    {
                        let i0 = new Int32Array(1);
                        let i1 = new Int32Array(1);
                        let i2 = new Int32Array(1);
                        let i3 = new Int32Array(1);
                        const r = CWGL.cwgl_getParameter_i4(ctx, pname, i0, i1, i2, i3);
                        if(r == 0){
                            //return Int32Array.of(i0[0], i1[0], i2[0], i3[0]);
                            const x = new Int32Array(4);
                            x[0] = i0[0];
                            x[1] = i1[0];
                            x[2] = i2[0];
                            x[3] = i3[0];
                            return x;
                        }else{
                            return null;
                        }
                    }
                    break;
                case "str":
                    {
                        let p0 = ptralloc();
                        const r = CWGL.cwgl_getParameter_str(ctx, pname, p0);
                        if(r == 0){
                            const s = ptrref(p0);
                            ptrfree(p0);
                            return consumestring(s);
                        }else{
                            return null;
                        }
                    }
                    break;
                case "float":
                    {
                        let f0 = new Float32Array(1);
                        const r = CWGL.cwgl_getParameter_f1(ctx, pname, f0);
                        if(r == 0){
                            return f0[0];
                        }else{
                            return null;
                        }
                    }
                    break;
                case "f2":
                    {
                        let f0 = new Float32Array(1);
                        let f1 = new Float32Array(1);
                        const r = CWGL.cwgl_getParameter_f2(ctx, pname, f0, f1);
                        if(r == 0){
                            //return Float32Array.of(f0[0], f1[0]);
                            const x = new Float32Array(2);
                            x[0] = f0[0];
                            x[1] = f1[0];
                            return x;
                        }else{
                            return null;
                        }
                    }
                    break;
                case "f4":
                    {
                        let f0 = new Float32Array(1);
                        let f1 = new Float32Array(1);
                        let f2 = new Float32Array(1);
                        let f3 = new Float32Array(1);
                        const r = CWGL.cwgl_getParameter_f4(ctx, pname, f0, f1, f2, f3);
                        if(r == 0){
                            //return Float32Array.of(f0[0], f1[0], f2[0], f3[0]);
                            const x = new Float32Array(4);
                            x[0] = f0[0];
                            x[1] = f1[0];
                            x[2] = f2[0];
                            x[3] = f3[0];
                            return x;
                        }else{
                            return null;
                        }
                    }
                    break;
                case "Buffer":
                case "Program":
                case "Framebuffer":
                case "Renderbuffer":
                case "Texture":
                    throw "unknown";
                default:
                    throw "invalid";
            }
        },
        /* WebGLHandlesContextLoss */
        getError: function(){
            // FIXME: Merge local error
            const server_error = CWGL.cwgl_getError(ctx);

            return server_error;
        },
        hint: function(target, mode){
            CWGL.cwgl_hint(ctx, target, mode);
        },
        /* WebGLHandlesContextLoss */
        isEnabled: function(cap){
            const b = CWGL.cwgl_isEnabled(ctx, cap);
            if(b == 0){
                return false;
            }else{
                return true;
            }
        },
        lineWidth: function(width){
            CWGL.cwgl_lineWidth(ctx, width);
        },
        pixelStorei: function(pname, param){
            // FIXME: Handle FLIP_Y
            CWGL.cwgl_pixelStorei(ctx, pname, param);
        },
        polygonOffset: function(factor, units){
            CWGL.cwgl_polygonOffset(ctx, factor, units);
        },
        sampleCoverage: function(value, invert){
            const i = invert ? 1 : 0;
            CWGL.cwgl_sampleCoverage(ctx, value, i);
        },
        stencilFunc: function(func, ref, mask){
            CWGL.cwgl_stencilFunc(ctx, func, ref, mask);
        },
        stencilFuncSeparate: function(face, func, ref, mask){
            CWGL.cwgl_stencilFuncSeparate(ctx, face, func, ref, mask);
        },
        stencilMask: function(mask){
            CWGL.cwgl_stencilMask(ctx, mask);
        },
        stencilMaskSeparate: function(face, mask){
            CWGL.cwgl_stencilMaskSeparate(ctx, face, mask);
        },
        stencilOp: function(fail, zfail, zpass){
            CWGL.cwgl_stencilOp(ctx, fail, zfail, zpass);
        },
        stencilOpSeparate: function(face, fail, zfail, zpass){
            CWGL.cwgl_stencilOpSeparate(ctx, face, fail, zfail, zpass);
        },
        // 5.14.4 Viewing and clipping
        scissor: function(x, y, width, height){
            CWGL.cwgl_scissor(ctx, x, y, width, height);
        },
        viewport: function(x, y, width, height){
            CWGL.cwgl_viewport(ctx, x, y, width, height);
        },
        // 5.14.5 Buffer objects
        bindBuffer: function(target, buffer){
            trackbinding_buffer(target, buffer);
            if(! buffer){
                CWGL.cwgl_bindBuffer(ctx, target, NULL);
            }else{
                CWGL.cwgl_bindBuffer(ctx, target, buffer.ptr);
            }
        },
        bufferData: function(target, data_or_size, usage){
            if(Number.isInteger(data_or_size)){
                const size = data_or_size;
                CWGL.cwgl_bufferData(ctx, target, size, NULL, usage);
            }else{
                const data = data_or_size;
                CWGL.cwgl_bufferData(ctx, target, data.byteLength, data, usage);
            }
        },
        bufferSubData: function(target, offset, data){
            CWGL.cwgl_bufferSubData(ctx, target, offset, data, data.byteLength);
        },
        createBuffer: function(){
            let ptr0 = CWGL.cwgl_createBuffer(ctx);
            const ptr = wrapPointer(ptr0, bufferfree);
            const r = {ptr: ptr};
            return r;
        },
        deleteBuffer: function(buffer){
            CWGL.cwgl_deleteBuffer(ctx, buffer.ptr);
        },
        getBufferParameter: function(target, pname){
            let i0 = new Int32Array(1);
            const r = CWGL.cwgl_getBufferParameter_i1(ctx, target, pname, i0);
            if(r == 0){
                return i0[0];
            }else{
                return null;
            }
        },
        isBuffer: function(buffer){
            const r = CWGL.cwgl_isBuffer(ctx, buffer.ptr);
            if(r == 0){
                return false;
            }else{
                return true;
            }
        },
        // 5.14.6 Framebuffer objects
        bindFramebuffer: function(target, framebuffer){
            trackbinding_Framebuffer(framebuffer);
            CWGL.cwgl_bindFramebuffer(ctx, target, objptr(framebuffer));
        },
        /* WebGLHandlesContextLoss */
        checkFramebufferStatus: function(target){
            return CWGL.cwgl_checkFramebufferStatus(ctx, target);
        },
        createFramebuffer: function(){
            let ptr0 = CWGL.cwgl_createFramebuffer(ctx);
            const ptr = wrapPointer(ptr0, framebufferfree);
            const r = {ptr: ptr};
            return r;
        },
        deleteFramebuffer: function(buffer){
            CWGL.cwgl_deleteFramebuffer(ctx, buffer.ptr);
        },
        framebufferRenderbuffer: function(target, attachment, renderbuffertarget, renderbuffer){
            if(attachment == E.DEPTH_STENCIL_ATTACHMENT){
                CWGL.cwgl_framebufferRenderbuffer(ctx, target, E.DEPTH_ATTACHMENT, renderbuffertarget, objptr(renderbuffer));
                CWGL.cwgl_framebufferRenderbuffer(ctx, target, E.STENCIL_ATTACHMENT, renderbuffertarget, objptr(renderbuffer));
            }else{
                CWGL.cwgl_framebufferRenderbuffer(ctx, target, attachment, renderbuffertarget, objptr(renderbuffer));
            }
        },
        framebufferTexture2D: function(target, attachment, textarget, texture, level){
            CWGL.cwgl_framebufferTexture2D(ctx, target, attachment, textarget, objptr(texture), level);
        },
        getFramebufferAttachmentParameter(target, attachment, pname){
            const type = getenumtype(pname);
            if(type == "int"){
                let i0 = new Int32Array(1);
                const r = CWGL.cwgl_getFramebufferAttachmentParameter_i1(ctx, target, attachment, pname, i0);
                if(r == 0){
                    return i0[0];
                }else{
                    return null;
                }
            }else{
                throw "unimpl";
            }
        },
        /* WebGLHandlesContextLoss */
        isFramebuffer: function(framebuffer){
            const r = CWGL.cwgl_isFramebuffer(ctx, framebuffer.ptr);
            if(r == 0){
                return false;
            }else{
                return true;
            }
        },
        // 5.14.7 Renderbuffer objects
        bindRenderbuffer: function(target, renderbuffer){
            trackbinding_Renderbuffer(renderbuffer);
            if(! renderbuffer){
                CWGL.cwgl_bindRenderbuffer(ctx, target, NULL);
            }else{
                CWGL.cwgl_bindRenderbuffer(ctx, target, renderbuffer.ptr);
            }
        },
        createRenderbuffer: function(){
            let ptr0 = CWGL.cwgl_createRenderbuffer(ctx);
            const ptr = wrapPointer(ptr0, renderbufferfree);
            const r = {ptr: ptr};
            return r;
        },
        deleteRenderbuffer: function(renderbuffer){
            CWGL.cwgl_deleteRenderbuffer(ctx, renderbuffer.ptr);
        },
        getRenderbufferParameter: function(target, pname){
            let i0 = new Int32Array(i);
            const r = CWGL.cwgl_getRenderbufferParameter(ctx, target, pname, i0);
            if(r == 0){
                return null;
            }else{
                return i0[0];
            }
        },
        /* WebGLHandlesContextLoss */
        isRenderbuffer(renderbuffer){
            const r = CWGL.cwgl_isRenderbuffer(ctx, renderbuffer.ptr);
            if(r == 0){
                return false;
            }else{
                return true;
            }
        },
        renderbufferStorage: function(target, internalformat, width, height){
            if(internalformat == E.DEPTH_STENCIL){
                CWGL.cwgl_renderbufferStorage(ctx, target, 0x88f0 /* Depth24 stencil8 */, width, height);
            }else if(internalformat == E.DEPTH_COMPONENT){
                CWGL.cwgl_renderbufferStorage(ctx, target, E.DEPTH_COMPONENT16, width, height);
            }else{
                CWGL.cwgl_renderbufferStorage(ctx, target, internalformat, width, height);
            }
        },
        // 5.14.8 Texture objects
        bindTexture: function(target, texture){
            trackbinding_texture(target, texture);
            if(! texture){
                CWGL.cwgl_bindTexture(ctx, target, NULL);
            }else{
                CWGL.cwgl_bindTexture(ctx, target, texture.ptr);
            }
        },
        // compressedTexImage2D
        // compressedTexSubImage2D
        copyTexImage2D: function(target, level, internalformat, x, y, width, height, border){
            CWGL.cwgl_copyTexImage2D(ctx, target, level, internalformat, x, y, width, height, border);
        },
        copyTexSubImage2D: function(target, level, xoffset, yoffset, x, y, width, height){
            CWGL.cwgl_copyTexSubImage2D(ctx, target, level, xoffset, yoffset, x, y, width, height);
        },
        createTexture: function(){
            let ptr0 = CWGL.cwgl_createTexture(ctx);
            const ptr = wrapPointer(ptr0, texfree);
            const r = {ptr: ptr};
            return r;
        },
        deleteTexture: function(tex){
            CWGL.cwgl_deleteTexture(ctx, tex.ptr);
        },
        generateMipmap: function(target){
            CWGL.cwgl_generateMipmap(ctx, target);
        },
        getTexParameter: function(target, pname){
            let i0 = new Int32Array(i);
            const r = CWGL.cwgl_getTexParameter(ctx, target, pname, i0);
            if(r == 0){
                return null;
            }else{
                return i0[0];
            }
        },
        /* WebGLHandlesContextLoss */
        isTexture: function(texture){
            const r = CWGL.cwgl_isTexture(ctx, texture.ptr);
            if(r == 0){
                return false;
            }else{
                return true;
            }
        },
        texImage2D: function(target, level, internalformat, width, height, border, format, type, pixels){
            // FIXME: No TexImageSource variant
            if(pixels == null){
                CWGL.cwgl_texImage2D(ctx, target, level, internalformat, width, height, border, format, type, NULL, 0);
            }else{
                CWGL.cwgl_texImage2D(ctx, target, level, internalformat, width, height, border, format, type, pixels, pixels.byteLength);
            }
        },
        texParameterf: function(target, pname, param){
            CWGL.cwgl_texParameterf(ctx, target, pname, param);
        },
        texParameteri: function(target, pname, param){
            CWGL.cwgl_texParameteri(ctx, target, pname, param);
        },
        texSubImage2D: function(target, level, xoffset, yoffset, width, height, format, type, pixels){
            // FIXME: No TexImageSource variant
            CWGL.cwgl_texSubImage2D(ctx, target, level, xoffset, yoffset, width, height, format, type, pixels, pixels.byteLength);
        },
        // 5.14.9 Programs and Shaders
        attachShader: function(program, shader){
            CWGL.cwgl_attachShader(ctx, program.ptr, shader);
        },
        bindAttribLocation: function(program, index, name){
            CWGL.cwgl_bindAttribLocation(ctx, program.ptr, index, name);
        },
        compileShader: function(shader){
            CWGL.cwgl_compileShader(ctx, shader);
        },
        createProgram: function(){
            let ptr0 = CWGL.cwgl_createProgram(ctx);
            const ptr = wrapPointer(ptr0, programfree);
            const r = {ptr: ptr};
            return r;
        },
        createShader: function(type){
            let ptr0 = CWGL.cwgl_createShader(ctx, type);
            const ptr = wrapPointer(ptr0, shaderfree);
            return ptr;
        },
        deleteProgram: function(program){
            CWGL.cwgl_deleteProgram(ctx, program.ptr);
        },
        deleteShader: function(shader){
            CWGL.cwgl_deleteShader(ctx, shader);
        },
        detachShader: function(program, shader){
            CWGL.cwgl_detachShader(ctx, program.ptr, shader);
        },
        // getAttachedShaders
        getProgramParameter: function(program, pname){
            const type = getenumtype(pname);
            if(type == "int"){
                let i0 = new Int32Array(1);
                const r = CWGL.cwgl_getProgramParameter_i1(ctx, program.ptr, pname, i0);
                if(r == 0){
                    return i0[0];
                }else{
                    return null;
                }
            }else if(type == "bool"){
                let i0 = new Int32Array(1);
                const r = CWGL.cwgl_getProgramParameter_i1(ctx, program.ptr, pname, i0);
                if(r == 0){
                    return i0[0] == 0 ? false : true;
                }else{
                    return null;
                }
            }else{
                throw "unimpl";
            }
        },
        getProgramInfoLog: function(program){
            const s = CWGL.cwgl_getProgramInfoLog(ctx, program.ptr);
            return consumestring(s);
        },
        getShaderParameter: function(shader, pname){
            const type = getenumtype(pname);
            if(type == "int"){
                let i0 = new Int32Array(1);
                const r = CWGL.cwgl_getShaderParameter_i1(ctx, shader, pname, i0);
                if(r == 0){
                    return i0[0];
                }else{
                    return null;
                }
            }else if(type == "bool"){
                let i0 = new Int32Array(1);
                const r = CWGL.cwgl_getShaderParameter_i1(ctx, shader, pname, i0);
                if(r == 0){
                    return i0[0] == 0 ? false : true;
                }else{
                    return null;
                }
            }else{
                throw "unimpl";
            }
        },
        getShaderPrecisionFormat: function(shadertype, precisiontype){
            let rangeMin = new Int32Array(1);
            let rangeMax = new Int32Array(1);
            let precision = new Int32Array(1);
            const r = CWGL.cwgl_getShaderPrecisionFormat(ctx, shadertype, precisiontype, rangeMin, rangeMax, precision);
            if(r == 0){
                return {
                    rangeMin: rangeMin[0],
                    rangeMax: rangeMax[0],
                    precision: precision[0]
                };
            }else{
                return null;
            }
        },
        getShaderInfoLog: function(shader){
            const s = CWGL.cwgl_getShaderInfoLog(ctx, shader);
            return consumestring(s);
        },
        getShaderSource: function(shader){
            const s = CWGL.cwgl_getShaderSource(ctx, shader);
            return consumestring(s);
        },
        /* WebGLHandlesContextLoss */
        isProgram: function(program){
            const r = CWGL.cwgl_isProgram(ctx, program.ptr);
            if(r == 0){
                return false;
            }else{
                return true;
            }
        },
        /* WebGLHandlesContextLoss */
        isShader: function(shader){
            const r = CWGL.cwgl_isShader(ctx, shader);
            if(r == 0){
                return false;
            }else{
                return true;
            }
        },
        linkProgram: function(program){
            CWGL.cwgl_linkProgram(ctx, program.ptr);
        },
        shaderSource: function(shader, source){
            // FIXME: Is it okay to use length here..?
            CWGL.cwgl_shaderSource(ctx, shader, source, source.length);
        },
        useProgram: function(program){
            trackbinding_program(program);
            if(program){
                CWGL.cwgl_useProgram(ctx, program.ptr);
            }else{
                CWGL.cwgl_useProgram(ctx, NULL);
            }
        },
        validateProgram: function(program){
            CWGL.cwgl_validateProgram(ctx, program.ptr);
        },
        // 5.14.10 Uniforms and attributes
        disableVertexAttribArray: function(index){
            CWGL.cwgl_disableVertexAttribArray(ctx, index);
        },
        enableVertexAttribArray: function(index){
            CWGL.cwgl_enableVertexAttribArray(ctx, index);
        },
        // getActiveAttrib
        getActiveUniform: function(program, index){
            let p0 = ptralloc();
            let i0 = new Int32Array(1);
            let i1 = new Int32Array(1);
            const r = CWGL.cwgl_getActiveUniform(ctx, program.ptr, index, i0, i1, p0);
            if(r == 0){
                const s = ptrref(p0);
                ptrfree(p0);
                const name = consumestring(s);
                return {
                    size: i0[0],
                    type: i1[0],
                    name: name
                };
            }else{
                return null;
            }
        },
        getAttribLocation: function(program, name){
            return CWGL.cwgl_getAttribLocation(ctx, program.ptr, name);
        },
        // getUniform
        getUniformLocation: function(program, name){
            let ptr0 = CWGL.cwgl_getUniformLocation(ctx, program.ptr, name);
            const ptr = wrapPointer(ptr0, uniformlocationfree);
            return ptr;
        },
        getVertexAttrib: function(index, pname){
            // FIXME: Implement this;
            const type = getenumtype(pname);
            switch(type){
                case "bool":
                    return false;
                case "int":
                    return 0;
                case "f4":
                    return [0.0,0.0,0.0,1.0];
                case "Buffer":
                    return null;
                default:
                    throw "unknown";
            }
        },
        /* WebGLHandlesContextLoss */
        getVertexAttribOffset: function(index){
            // FIXME: Implement this;
            return 0;
        },
        uniform1f: function(loc, x){
            CWGL.cwgl_uniform1f(ctx, loc, x);
        },
        uniform2f: function(loc, x, y){
            CWGL.cwgl_uniform2f(ctx, loc, x, y);
        },
        uniform3f: function(loc, x, y, z){
            CWGL.cwgl_uniform3f(ctx, loc, x, y, z);
        },
        uniform4f: function(loc, x, y, z, w){
            CWGL.cwgl_uniform4f(ctx, loc, x, y, z, w);
        },
        uniform1i: function(loc, x){
            CWGL.cwgl_uniform1i(ctx, loc, x);
        },
        uniform2i: function(loc, x, y){
            CWGL.cwgl_uniform2i(ctx, loc, x, y);
        },
        uniform3i: function(loc, x, y, z){
            CWGL.cwgl_uniform3i(ctx, loc, x, y, z);
        },
        uniform4i: function(loc, x, y, z, w){
            CWGL.cwgl_uniform4i(ctx, loc, x, y, z, w);
        },
        uniform1fv: function(loc, v){
            CWGL.cwgl_uniform1fv(ctx, loc, v, v.length);
        },
        uniform2fv: function(loc, v){
            CWGL.cwgl_uniform2fv(ctx, loc, v, v.length / 2);
        },
        uniform3fv: function(loc, v){
            CWGL.cwgl_uniform3fv(ctx, loc, v, v.length / 3);
        },
        uniform4fv: function(loc, v){
            CWGL.cwgl_uniform4fv(ctx, loc, v, v.length / 4);
        },
        uniform1iv: function(loc, v){
            CWGL.cwgl_uniform1iv(ctx, loc, v, v.length);
        },
        uniform2iv: function(loc, v){
            if(!loc) return; // Godot WebGL1 WAR
            CWGL.cwgl_uniform2iv(ctx, loc, v, v.length / 2);
        },
        uniform3iv: function(loc, v){
            CWGL.cwgl_uniform3iv(ctx, loc, v, v.length / 3);
        },
        uniform4iv: function(loc, v){
            CWGL.cwgl_uniform4iv(ctx, loc, v, v.length / 4);
        },
        uniformMatrix2fv: function(loc, transpose, v){
            const t = transpose ? 1 : 0;
            const cnt = v.length / 4;
            CWGL.cwgl_uniformMatrix2fv(ctx, loc, t, v, cnt);
        },
        uniformMatrix3fv: function(loc, transpose, v){
            const t = transpose ? 1 : 0;
            const cnt = v.length / 9;
            CWGL.cwgl_uniformMatrix3fv(ctx, loc, t, v, cnt);
        },
        uniformMatrix4fv: function(loc, transpose, v){
            const t = transpose ? 1 : 0;
            const cnt = v.length / 16;
            CWGL.cwgl_uniformMatrix4fv(ctx, loc, t, v, cnt);
        },
        vertexAttrib1f: function(index, x){
            CWGL.cwgl_vertexAttrib1f(ctx, index, x);
        },
        vertexAttrib2f: function(index, x, y){
            CWGL.cwgl_vertexAttrib2f(ctx, index, x, y);
        },
        vertexAttrib3f: function(index, x, y, z){
            CWGL.cwgl_vertexAttrib3f(ctx, index, x, y, z);
        },
        vertexAttrib4f: function(index, x, y, z, w){
            CWGL.cwgl_vertexAttrib4f(ctx, index, x, y, z, w);
        },
        vertexAttrib1fv: function(index, v){
            CWGL.cwgl_vertexAttrib1f(ctx, index, v[0]);
        },
        vertexAttrib2fv: function(index, v){
            CWGL.cwgl_vertexAttrib2f(ctx, index, v[0], v[1]);
        },
        vertexAttrib3fv: function(index, v){
            CWGL.cwgl_vertexAttrib3f(ctx, index, v[0], v[1], v[2]);
        },
        vertexAttrib4fv: function(index, v){
            CWGL.cwgl_vertexAttrib4f(ctx, index, v[0], v[1], v[2], v[3]);
        },
        vertexAttribPointer: function(index, size, type, normalized, stride, offset){
            const n = normalized ? 1 : 0;
            CWGL.cwgl_vertexAttribPointer(ctx, index, size, type, n, stride, offset);
        },
        // 5.14.11 Writing to the drawing buffer
        clear: function(mask){
            CWGL.cwgl_clear(ctx, mask);
        },
        drawArrays: function(mode, first, count){
            CWGL.cwgl_drawArrays(ctx, mode, first, count);
        },
        drawElements: function(mode, count, type, offset){
            CWGL.cwgl_drawElements(ctx, mode, count, type, offset);
        },
        finish: function(){
            CWGL.cwgl_finish(ctx);
        },
        flush: function(){
            CWGL.cwgl_flush(ctx);
        },
        // 5.14.12 Reading back pixels
        readPixels: function(x, y, width, height, format, type, pixels){
            CWGL.cwgl_readPixels(ctx, x, y, width, height, format, type, pixels, pixels.byteLength);
        },
        // 5.14.13 Detecting context lost events
        /* WebGLHandlesContextLoss */
        isContextLost: function(){
            return false;
        },
        // 5.14.14 Detecting and enabling extensions
        getSupportedExtensions: function(){
            return ["OES_element_index_uint", "OES_vertex_array_object"];
        },
        getExtension: function(name){
            switch(name){
                default:
                    return null;
                case "OES_vertex_array_object":
                    return {
                        VERTEX_ARRAY_BINDING_OES: 0x85B5,
                        createVertexArrayOES: function(){
                            let ptr0 = CWGL.cwgl_createVertexArray(ctx);
                            const ptr = wrapPointer(ptr0, "should not happen");
                            const r = {ptr: ptr};
                            return r;
                        },
                        deleteVertexArrayOES: "UNIMPL",
                        isVertexArrayOES: "UNIMPL",
                        bindVertexArrayOES: function(arrayObject){
                            if(! arrayObject){
                                CWGL.cwgl_bindVertexArray(ctx, NULL);
                            }else{
                                CWGL.cwgl_bindVertexArray(ctx, arrayObject.ptr);
                            }
                        }
                    };
            }
            return null;
        },

    };

    // Fill-in GL enums
    Object.assign(R, E);

    return R;
}

export default GL;
