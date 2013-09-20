
#include <node.h>
#include <node_buffer.h>
#include <string.h>
#include <mcrypt.h>
#include "mcrypt.h"

using namespace v8;

MCrypt::MCrypt() {};
MCrypt::~MCrypt() {
    mcrypt_module_close(mcrypt_);
};

Handle<Value> MCrypt::New(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 2) {
        return ThrowException(String::New("Missing parameters. Algorithm and mode should be specified."));
    }

    String::AsciiValue algo(args[0]);
    String::AsciiValue mode(args[1]);
    String::AsciiValue algoDir(args[2]);
    String::AsciiValue modeDir(args[3]);

    MCrypt* obj = new MCrypt();
    obj->mcrypt_ = mcrypt_module_open(*algo, *algoDir, *mode, *modeDir);
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module can not open."));
    }
    
    obj->Wrap(args.This());

    return args.This();
}

Handle<Value> MCrypt::Encrypt(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 1) {
        return ThrowException(String::New("Missing parameter. Plaintext should be specified."));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    char* text = NULL;
    int len = 0;
    String::AsciiValue* st;

    if (args[0]->IsString()) {
        Local<String> param = Local<String>::Cast(args[0]);
        len = param->Length();

        st = new String::AsciiValue(param);
        text = **st;
    } else if (node::Buffer::HasInstance(args[0])) {
        text = node::Buffer::Data(args[0]);
        len = node::Buffer::Length(args[0]);
    } else {
        return ThrowException(String::New("Plaintext has got incorrect type. Should be Buffer or String"));
    }

    
    int dataSize = len;
    
    if (mcrypt_enc_is_block_algorithm(obj->mcrypt_) == 1) {
        int blockSize = mcrypt_enc_get_block_size(obj->mcrypt_);
        dataSize = (((len - 1) / blockSize) + 1) * blockSize;
    }
    
    node::Buffer* buffer = node::Buffer::New(dataSize);
    memset(node::Buffer::Data(buffer), 0, dataSize);
    memcpy(node::Buffer::Data(buffer), text, len);
    
    int result = 0;
    
    if ((result = mcrypt_generic(obj->mcrypt_, node::Buffer::Data(buffer), dataSize)) != 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(String::New(error));
    }
    
    return scope.Close(buffer->handle_);
}

Handle<Value> MCrypt::Decrypt(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 1) {
        return ThrowException(String::New("Missing parameter. Ciphertext should be specified."));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    char* text = NULL;
    int len = 0;
    String::AsciiValue* st;

    if (args[0]->IsString()) {
        Local<String> param = Local<String>::Cast(args[0]);
        len = param->Length();

        st = new String::AsciiValue(param);
        text = **st;
    } else if (node::Buffer::HasInstance(args[0])) {
        text = node::Buffer::Data(args[0]);
        len = node::Buffer::Length(args[0]);
    } else {
        return ThrowException(String::New("Ciphertext has got incorrect type. Should be Buffer or String"));
    }

    
    int dataSize = len;
    
    if (mcrypt_enc_is_block_algorithm(obj->mcrypt_) == 1) {
        int blockSize = mcrypt_enc_get_block_size(obj->mcrypt_);
        dataSize = (((len - 1) / blockSize) + 1) * blockSize;
    }
    
    node::Buffer* buffer = node::Buffer::New(dataSize);
    memset(node::Buffer::Data(buffer), 0, dataSize);
    memcpy(node::Buffer::Data(buffer), text, len);
    
    int result = 0;
    
    if ((result = mdecrypt_generic(obj->mcrypt_, node::Buffer::Data(buffer), dataSize)) != 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(String::New(error));
    }
    
    return scope.Close(buffer->handle_);
}

Handle<Value> MCrypt::Open(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return ThrowException(String::New("Missing parameter. Key should be specified."));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    String::AsciiValue key(args[0]);
    String::AsciiValue iv(args[1]);
    
    int result = 0;
    
    if ((result = mcrypt_generic_init(obj->mcrypt_, *key, key.length(), *iv)) < 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(String::New(error));
    }
    
    return scope.Close(Undefined());
}

Handle<Value> MCrypt::SetState(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 1) {
        return ThrowException(String::New("Missing parameter. State should be specified."));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    String::AsciiValue state(args[0]);
    
    int result = 0;
    
    if ((result = mcrypt_enc_set_state(obj->mcrypt_, *state, state.length())) != 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(String::New(error));
    }
    
    return scope.Close(Undefined());
}

Handle<Value> MCrypt::GetState(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    char *state = NULL;
    int len = 0;
    
    int result = 0;
    
    if ((result = mcrypt_enc_get_state(obj->mcrypt_, state, &len)) != 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(String::New(error));
    }
    
    return scope.Close(String::New(state, len));
}

Handle<Value> MCrypt::SelfTest(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int result = 0;
    
    if ((result = mcrypt_enc_self_test(obj->mcrypt_)) == 0) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::IsBlockAlgorithmMode(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int result = 0;
    
    if ((result = mcrypt_enc_is_block_algorithm_mode(obj->mcrypt_)) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::IsBlockAlgorithm(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int result = 0;
    
    if ((result = mcrypt_enc_is_block_algorithm(obj->mcrypt_)) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::IsBlockMode(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int result = 0;
    
    if ((result = mcrypt_enc_is_block_mode(obj->mcrypt_)) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::GetBlockSize(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int blockSize = mcrypt_enc_get_block_size(obj->mcrypt_);
    
    return scope.Close(Number::New(blockSize));
}

Handle<Value> MCrypt::GetKeySize(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int keySize = mcrypt_enc_get_key_size(obj->mcrypt_);
    
    return scope.Close(Number::New(keySize));
}

Handle<Value> MCrypt::GetSupportedKeySizes(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int count;
    int* sizes = mcrypt_enc_get_supported_key_sizes(obj->mcrypt_, &count);
    
    Handle<Array> array = Array::New(count);
    
    if (array.IsEmpty()) {
        return Handle<Array>();
    }
    
    for (int i = 0; i < count; i++) {
        array->Set(i, Number::New(sizes[i]));
    }
    
    mcrypt_free(sizes);
    
    return scope.Close(array);
}

Handle<Value> MCrypt::GetIvSize(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int ivSize = mcrypt_enc_get_iv_size(obj->mcrypt_);
    
    return scope.Close(Number::New(ivSize));
}

Handle<Value> MCrypt::HasIv(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int result = 0;
    
    if ((result = mcrypt_enc_mode_has_iv(obj->mcrypt_)) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::GetAlgorithmName(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    char* name = mcrypt_enc_get_algorithms_name(obj->mcrypt_);
    Handle<String> ret = String::New(name);
    mcrypt_free(name);
    
    return scope.Close(ret);
}

Handle<Value> MCrypt::GetModeName(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    char* name = mcrypt_enc_get_modes_name(obj->mcrypt_);
    Handle<String> ret = String::New(name);
    mcrypt_free(name);
    
    return scope.Close(ret);
}

Handle<Value> MCrypt::Close(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(String::New("MCrypt module was not open."));
    }
    
    int result = 0;
    
    if ((result = mcrypt_generic_deinit(obj->mcrypt_)) < 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(String::New(error));
    }
    
    return scope.Close(Undefined());
}

Handle<Value> MCrypt::GetAlgorithmNames(const Arguments& args) {
    HandleScope scope;
    
    char* path = NULL;
    if (!args[0]->IsUndefined()) {
        String::AsciiValue st(args[0]);
        path = *st;
    }
    
    int size = 0;
    char** algos = mcrypt_list_algorithms(path, &size);
    
    Handle<Array> array = Array::New(size);
    
    if (array.IsEmpty()) {
        return Handle<Array>();
    }
    
    for (int i = 0; i < size; i++) {
        array->Set(i, String::New(algos[i]));
    }
    
    mcrypt_free_p(algos, size);
    
    return scope.Close(array);
}

Handle<Value> MCrypt::GetModeNames(const Arguments& args) {
    HandleScope scope;
    
    char* path = NULL;
    if (!args[0]->IsUndefined()) {
        String::AsciiValue st(args[0]);
        path = *st;
    }
    
    int size = 0;
    char** modes = mcrypt_list_modes(path, &size);
    
    Handle<Array> array = Array::New(size);
    
    if (array.IsEmpty())
        return Handle<Array>();
    
    for (int i = 0; i < size; i++) {
        array->Set(i, String::New(modes[i]));
    }
    
    mcrypt_free_p(modes, size);
    
    return scope.Close(array);
}

void MCrypt::Init(Handle<Object> exports) {

    Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
    tpl->SetClassName(String::NewSymbol("MCrypt"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    
    Local<ObjectTemplate> prototype = tpl->PrototypeTemplate();
    
    // prototype
    
    prototype->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(Encrypt)->GetFunction());
    prototype->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(Decrypt)->GetFunction());
    prototype->Set(String::NewSymbol("open"), FunctionTemplate::New(Open)->GetFunction());
    prototype->Set(String::NewSymbol("setState"), FunctionTemplate::New(SetState)->GetFunction());
    prototype->Set(String::NewSymbol("getState"), FunctionTemplate::New(GetState)->GetFunction());
    prototype->Set(String::NewSymbol("selfTest"), FunctionTemplate::New(SelfTest)->GetFunction());
    prototype->Set(String::NewSymbol("isBlockAlgorithmMode"), FunctionTemplate::New(IsBlockAlgorithmMode)->GetFunction());
    prototype->Set(String::NewSymbol("isBlockAlgorithm"), FunctionTemplate::New(IsBlockAlgorithm)->GetFunction());
    prototype->Set(String::NewSymbol("isBlockMode"), FunctionTemplate::New(IsBlockMode)->GetFunction());
    prototype->Set(String::NewSymbol("getBlockSize"), FunctionTemplate::New(GetBlockSize)->GetFunction());
    prototype->Set(String::NewSymbol("getKeySize"), FunctionTemplate::New(GetKeySize)->GetFunction());
    prototype->Set(String::NewSymbol("getSupportedKeySizes"), FunctionTemplate::New(GetSupportedKeySizes)->GetFunction());
    prototype->Set(String::NewSymbol("getIvSize"), FunctionTemplate::New(GetIvSize)->GetFunction());
    prototype->Set(String::NewSymbol("hasIv"), FunctionTemplate::New(HasIv)->GetFunction());
    prototype->Set(String::NewSymbol("getAlgorithmName"), FunctionTemplate::New(GetAlgorithmName)->GetFunction());
    prototype->Set(String::NewSymbol("getModeName"), FunctionTemplate::New(GetModeName)->GetFunction());
    prototype->Set(String::NewSymbol("close"), FunctionTemplate::New(Close)->GetFunction());
    
    // exports

    exports->Set(String::NewSymbol("MCrypt"), Persistent<Function>::New(tpl->GetFunction()));
    exports->Set(String::NewSymbol("getAlgorithmNames"), FunctionTemplate::New(GetAlgorithmNames)->GetFunction());
    exports->Set(String::NewSymbol("getModeNames"), FunctionTemplate::New(GetModeNames)->GetFunction());
    
}

NODE_MODULE(mcrypt, MCrypt::Init)
