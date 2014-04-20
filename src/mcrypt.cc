
#include <cstdlib>
#include <cstring>

#include <node.h>
#include <node_buffer.h>
#include <mcrypt.h>

#include "mcrypt.h"

using namespace v8;

Persistent<Function> MCrypt::constructor;

MCrypt::MCrypt() {};
MCrypt::~MCrypt() {
    mcrypt_module_close(mcrypt_);
};

Handle<Value> MCrypt::New(const Arguments& args) {
    HandleScope scope;
    
    if (!args.IsConstructCall()) {
        const int argc = 2;
        Local<Value> argv[argc] = {args[0], args[1]};
        return scope.Close(constructor->NewInstance(argc, argv));
    }
    
    if (args.Length() < 2) {
        return ThrowException(Exception::TypeError(String::New("Missing parameters. Algorithm and mode should be specified.")));
    }

    String::AsciiValue algo(args[0]);
    String::AsciiValue mode(args[1]);
    String::AsciiValue algoDir(args[2]);
    String::AsciiValue modeDir(args[3]);

    MCrypt* obj = new MCrypt();
    obj->mcrypt_ = mcrypt_module_open(*algo, *algoDir, *mode, *modeDir);
    obj->checkKeySize = true;
    obj->checkIvSize = true;
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module can not open.")));
    }
    
    obj->Wrap(args.This());

    return args.This();
}

Handle<Value> MCrypt::Encrypt(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 1) {
        return ThrowException(Exception::TypeError(String::New("Missing parameter. Plaintext should be specified.")));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    char* text = NULL;
    unsigned long int len = 0;
    String::AsciiValue* st;

    if (args[0]->IsString()) {
        st = new String::AsciiValue(args[0]);
        text = **st;
        len = st->length();
    } else if (node::Buffer::HasInstance(args[0])) {
        text = node::Buffer::Data(args[0]);
        len = node::Buffer::Length(args[0]);
    } else {
        return ThrowException(Exception::TypeError(String::New("Plaintext has got incorrect type. Should be Buffer or String.")));
    }
    
    unsigned long int dataSize = len;
    
    if (mcrypt_enc_is_block_algorithm(obj->mcrypt_) == 1) {
        int blockSize = mcrypt_enc_get_block_size(obj->mcrypt_);
        dataSize = (((len - 1) / blockSize) + 1) * blockSize;   
    }

    char* data;
    data = (char*) malloc(dataSize + 1);

    memset(data, 0, dataSize);
    memcpy(data, text, len);
    
    int result = 0;
    
    if ((result = mcrypt_generic_init(obj->mcrypt_, (void *) obj->key, obj->keyLen, (void *) obj->iv)) < 0) {
        free(data);
        const char* error = mcrypt_strerror(result);
        return ThrowException(Exception::Error(String::New(error)));
    }
    
    if ((result = mcrypt_generic(obj->mcrypt_, data, dataSize)) != 0) {
        free(data);
        const char* error = mcrypt_strerror(result);
        return ThrowException(Exception::Error(String::New(error)));
    }
    
    if ((result = mcrypt_generic_deinit(obj->mcrypt_)) < 0) {
        free(data);
        const char* error = mcrypt_strerror(result);
        return ThrowException(Exception::Error(String::New(error)));
    }
    
    data[dataSize] = 0;
    
    node::Buffer* buffer = node::Buffer::New(data, dataSize);
    free(data);
    return scope.Close(buffer->handle_);
}

Handle<Value> MCrypt::Decrypt(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 1) {
        return ThrowException(Exception::TypeError(String::New("Missing parameter. Ciphertext should be specified.")));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    char* text = NULL;
    unsigned long int len = 0;

    if (node::Buffer::HasInstance(args[0])) {
        text = node::Buffer::Data(args[0]);
        len = node::Buffer::Length(args[0]);
    } else {
        return ThrowException(Exception::TypeError(String::New("Ciphertext has got incorrect type. Should be Buffer.")));
    }
    
    unsigned long int dataSize = len;
    
    if (mcrypt_enc_is_block_algorithm(obj->mcrypt_) == 1) {
        int blockSize = mcrypt_enc_get_block_size(obj->mcrypt_);
        dataSize = (((len - 1) / blockSize) + 1) * blockSize;
    }

    char * data;
    data = (char*) malloc(dataSize + 1);
    
    memset(data, 0, dataSize);
    memcpy(data, text, len);
    
    int result = 0;
    
    if ((result = mcrypt_generic_init(obj->mcrypt_, (void *) obj->key, obj->keyLen, (void *) obj->iv)) < 0) {
        const char* error = mcrypt_strerror(result);
        return ThrowException(Exception::Error(String::New(error)));
    }
    
    if ((result = mdecrypt_generic(obj->mcrypt_, data, dataSize)) != 0) {
        free(data);
        const char* error = mcrypt_strerror(result);
        return ThrowException(Exception::Error(String::New(error)));
    }
    
    if ((result = mcrypt_generic_deinit(obj->mcrypt_)) < 0) {
        free(data);
        const char* error = mcrypt_strerror(result);
        return ThrowException(Exception::Error(String::New(error)));
    }

    data[dataSize] = 0;

    node::Buffer* buffer = node::Buffer::New(data, dataSize);
    free(data);
    return scope.Close(buffer->handle_);
}

Handle<Value> MCrypt::Open(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return ThrowException(Exception::TypeError(String::New("Missing parameter. Key should be specified.")));
    }
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }

    String::AsciiValue* st1;
    
    if (args[0]->IsString()) {
        st1 = new String::AsciiValue(args[0]);
        obj->key = **st1;
        obj->keyLen = st1->length();
    } else if (node::Buffer::HasInstance(args[0])) {
        obj->key = node::Buffer::Data(args[0]);
        obj->keyLen = node::Buffer::Length(args[0]);
    } else {
        return ThrowException(Exception::TypeError(String::New("Key has got incorrect type. Should be Buffer or String.")));
    }

    if (obj->checkKeySize) {
        int count = 0;
        int* sizes = mcrypt_enc_get_supported_key_sizes(obj->mcrypt_, &count);

        bool invalid = true; 

        if (count > 0) {
            for (int i = 0; i < count; i++) {
                if (sizes[i] == obj->keyLen) {
                    invalid = false;
                    break;
                }
            }
        } else {
            int size = mcrypt_enc_get_key_size(obj->mcrypt_);
            if ((size <= 0) || (size == obj->keyLen)) {
                invalid = false;
            }
        }
    
        mcrypt_free(sizes);
        
        if (invalid) {
            return ThrowException(Exception::TypeError(String::New("Invalid key size. You can determine key sizes using getSupportedKeySizes()")));
        }
    }

    String::AsciiValue* st2;
    size_t ivLen;

    if (!args[1]->IsUndefined()) {
        if (args[1]->IsString()) {
            st2 = new String::AsciiValue(args[1]);
            obj->iv = **st2;
            ivLen = st2->length();
        } else if (node::Buffer::HasInstance(args[1])) {
            obj->iv = node::Buffer::Data(args[1]);
            ivLen = node::Buffer::Length(args[1]);
        } else {
            return ThrowException(Exception::TypeError(String::New("Iv has got incorrect type. Should be Buffer or String.")));
        }
        
        if (obj->checkIvSize) {
            if ((size_t)mcrypt_enc_get_iv_size(obj->mcrypt_) != ivLen) {
                return ThrowException(Exception::TypeError(String::New("Invalid iv size. You can determine iv size using getIvSize()")));
            }
        }
    }
    
    return scope.Close(Undefined());
}

Handle<Value> MCrypt::ValidateKeySize(const Arguments& args) {
    HandleScope scope;

    if(args.Length() == 0) {
        return scope.Close(Undefined());
    }

    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    Local<Boolean> state = args[0]->ToBoolean();
    obj->checkKeySize = state->Value();

    return scope.Close(Undefined());
}

Handle<Value> MCrypt::ValidateIvSize(const Arguments& args) {
    HandleScope scope;

    if(args.Length() == 0) {
        return scope.Close(Undefined());
    }

    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());
    Local<Boolean> state = args[0]->ToBoolean();
    obj->checkIvSize = state->Value();

    return scope.Close(Undefined());
}

Handle<Value> MCrypt::SelfTest(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }

    if (mcrypt_enc_self_test(obj->mcrypt_) == 0) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::IsBlockAlgorithmMode(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    if (mcrypt_enc_is_block_algorithm_mode(obj->mcrypt_) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::IsBlockAlgorithm(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    if (mcrypt_enc_is_block_algorithm(obj->mcrypt_) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::IsBlockMode(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    if (mcrypt_enc_is_block_mode(obj->mcrypt_) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::GetBlockSize(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    int blockSize = mcrypt_enc_get_block_size(obj->mcrypt_);
    
    return scope.Close(Number::New(blockSize));
}

Handle<Value> MCrypt::GetKeySize(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    int keySize = mcrypt_enc_get_key_size(obj->mcrypt_);
    
    return scope.Close(Number::New(keySize));
}

Handle<Value> MCrypt::GetSupportedKeySizes(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
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
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    int ivSize = mcrypt_enc_get_iv_size(obj->mcrypt_);
    
    return scope.Close(Number::New(ivSize));
}

Handle<Value> MCrypt::HasIv(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    if (mcrypt_enc_mode_has_iv(obj->mcrypt_) == 1) {
        return scope.Close(True());
    }
    
    return scope.Close(False());
}

Handle<Value> MCrypt::GetAlgorithmName(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
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
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    char* name = mcrypt_enc_get_modes_name(obj->mcrypt_);
    Handle<String> ret = String::New(name);
    mcrypt_free(name);
    
    return scope.Close(ret);
}

Handle<Value> MCrypt::GenerateIv(const Arguments& args) {
    HandleScope scope;
    
    MCrypt* obj = ObjectWrap::Unwrap<MCrypt>(args.This());

    if (obj->mcrypt_ == MCRYPT_FAILED) {
        return ThrowException(Exception::ReferenceError(String::New("MCrypt module was not open.")));
    }
    
    int ivSize = mcrypt_enc_get_iv_size(obj->mcrypt_);
    
    node::Buffer* buffer = node::Buffer::New(ivSize);
    
    char* iv = node::Buffer::Data(buffer);
    
    while(ivSize) {
        iv[--ivSize] = 255.0 * std::rand() / RAND_MAX;
    }
    
    return scope.Close(buffer->handle_);
}

Handle<Value> MCrypt::GetAlgorithmNames(const Arguments& args) {
    HandleScope scope;
    
    String::AsciiValue path(args[0]);
    
    int size = 0;
    char** algos = mcrypt_list_algorithms(*path, &size);
    
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
    
    String::AsciiValue path(args[0]);
    
    int size = 0;
    char** modes = mcrypt_list_modes(*path, &size);
    
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
    tpl->InstanceTemplate()->SetInternalFieldCount(6);
    
    Local<ObjectTemplate> prototype = tpl->PrototypeTemplate();
    
    // prototype
    prototype->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(Encrypt)->GetFunction());
    prototype->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(Decrypt)->GetFunction());
    prototype->Set(String::NewSymbol("open"), FunctionTemplate::New(Open)->GetFunction());
    prototype->Set(String::NewSymbol("validateKeySize"), FunctionTemplate::New(ValidateKeySize)->GetFunction());
    prototype->Set(String::NewSymbol("validateIvSize"), FunctionTemplate::New(ValidateIvSize)->GetFunction());
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
    prototype->Set(String::NewSymbol("generateIv"), FunctionTemplate::New(GenerateIv)->GetFunction());
    
    // exports
    constructor = Persistent<Function>::New(tpl->GetFunction());
    exports->Set(String::NewSymbol("MCrypt"), constructor);
    exports->Set(String::NewSymbol("getAlgorithmNames"), FunctionTemplate::New(GetAlgorithmNames)->GetFunction());
    exports->Set(String::NewSymbol("getModeNames"), FunctionTemplate::New(GetModeNames)->GetFunction());
}

NODE_MODULE(mcrypt, MCrypt::Init)
