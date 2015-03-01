

#include "mcrypt.h"

using namespace v8;

Persistent<Function> MCrypt::constructor;

MCrypt::MCrypt(_NAN_METHOD_ARGS_TYPE args): 
    checkKeySize(true), 
    checkIvSize(true),
    algo(args[0]), 
    mode(args[1]), 
    algoDir(args[2]), 
    modeDir(args[3]) {

    mcrypt_ = mcrypt_module_open(*algo, *algoDir, *mode, *modeDir);
};

MCrypt::~MCrypt() {
    mcrypt_module_close(mcrypt_);
};


template <int (*modify)(MCRYPT mcrypt, void* target, int length)>
char* MCrypt::transform(const char* plainText, size_t* length, int* result) { 
    const size_t origLength = *length;

    // determine allocation size if the cipher algorithm is block mode
    // block mode algorithm needs to fit in modulus of block size
    // and it needs to padding space if not fit into block size
    if (mcrypt_enc_is_block_algorithm(mcrypt_) == 1) {
        size_t blockSize = mcrypt_enc_get_block_size(mcrypt_);
        *length = (((*length - 1) / blockSize) + 1) * blockSize;
    }

    char* targetData = new char[*length]();
    std::copy(plainText, plainText + origLength, targetData);
    
    // copy of the key and iv due to mcrypt_generic_init not accepts 
    // const char for key and iv. direct passing is not safe because
    // iv and key could be modified by mcrypt_generic_init in this case
    char keyBuf[key.length()];
    key.copy(keyBuf, key.length());
    
    char ivBuf[iv.length()];
    iv.copy(ivBuf, iv.length());
    
    if ((*result = mcrypt_generic_init(mcrypt_, keyBuf, key.length(), ivBuf)) < 0) {
        return targetData;
    }

    if ((*result = modify(mcrypt_, targetData, *length)) != 0) {
        return targetData;
    }

    *result = mcrypt_generic_deinit(mcrypt_);

    return targetData;
}

std::vector<size_t> MCrypt::getKeySizes() {
    
    int count = 0;
    int* sizes = mcrypt_enc_get_supported_key_sizes(mcrypt_, &count);

    if (count <= 0) {
        mcrypt_free(sizes);

        size_t size = mcrypt_enc_get_key_size(mcrypt_);

        if (size > 0) {
            std::vector<size_t> keySizes(1);
            keySizes[0] = size;
            return keySizes;
        }

        std::vector<size_t> keySizes(0);
        return keySizes;
    }

    std::vector<size_t> keySizes(count);

    for (int i = 0; i < count; i++) {
        keySizes[i] = sizes[i];
    }

    mcrypt_free(sizes);
    
    return keySizes;
}

NAN_METHOD(MCrypt::New) {
    NanScope();
    
    if (!args.IsConstructCall()) {
        Local<Value> argv[] = {args[0], args[1], args[2], args[3]};
        Local<Function> cons = NanNew<Function>(constructor);
        NanReturnValue(cons->NewInstance(4, argv));
    }

    if (args.Length() < 2) {
        NanThrowTypeError("Missing parameters. Algorithm and mode should be specified.");
    }

    MCrypt* mcrypt = new MCrypt(args);

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    mcrypt->Wrap(args.This());

    NanReturnValue(args.This());
}

NAN_METHOD(MCrypt::Open) {
    NanScope();

    if (args.Length() < 1) {
        NanThrowTypeError("Missing parameter. Key should be specified.");
    }
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (args[0]->IsString()) {
        NanUtf8String value(args[0]);
    
        mcrypt->key = std::string(*value, value.length());

    } else if (node::Buffer::HasInstance(args[0])) { 
    
        mcrypt->key = std::string(node::Buffer::Data(args[0]), node::Buffer::Length(args[0]));

    } else {
        NanThrowTypeError("Key has got incorrect type. Should be Buffer or String.");
    }

    if (mcrypt->checkKeySize) {
        std::vector<size_t> keySizes = mcrypt->getKeySizes();
    
        if (keySizes.size() > 0) {

            bool invalid = true;
            
            std::stringstream serror;
            
            serror << "Invalid key size. Available key size are [";
            
            for(size_t i = 0; i < keySizes.size(); i++) {
                
                if (i != 0) {
                    serror << ", ";
                }
                
                serror << keySizes[i];
                
                if (keySizes[i] == mcrypt->key.length()) {
                    invalid = false;
                }
            }

            serror << "]";
            
            std::string error = serror.str();

            if (invalid) {
                NanThrowTypeError(error.c_str());
            }
        }
    }

    if (args[1]->IsUndefined()) {
        NanReturnUndefined();
    }

    size_t ivLen = 0;

    if (args[1]->IsString()) {
        
        NanUtf8String value(args[1]);

        ivLen = value.length();
        mcrypt->iv = std::string(*value, ivLen);

    } else if (node::Buffer::HasInstance(args[1])) {

        ivLen = node::Buffer::Length(args[1]);
        mcrypt->iv = std::string(node::Buffer::Data(args[1]), ivLen);
    } else {
        NanThrowTypeError("Iv has got incorrect type. Should be Buffer or String.");
    }

    if (mcrypt->checkIvSize) {
        if ((size_t)mcrypt_enc_get_iv_size(mcrypt->mcrypt_) != ivLen) {
            NanThrowTypeError("Invalid iv size. You can determine iv size using getIvSize()");
        }
    }
    
    NanReturnUndefined();
}

NAN_METHOD(MCrypt::Encrypt) {
    NanScope();
    
    if (args.Length() < 1) {
        NanThrowTypeError("Missing parameter. Plaintext should be specified.");
    }
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This()); 
    
    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int result = 0;
    char* cipherText = {0};
    size_t length = 0;

    if (args[0]->IsString()) {

        NanUtf8String value(args[0]);
        length = value.length();
        cipherText = mcrypt->transform<mcrypt_generic>(*value, &length, &result);

    } else if(node::Buffer::HasInstance(args[0])) {

        length = node::Buffer::Length(args[0]);
        cipherText = mcrypt->transform<mcrypt_generic>(node::Buffer::Data(args[0]), &length, &result); 
        
    } else {
        NanThrowTypeError("Plaintext has got incorrect type. Should be Buffer or String.");
    }
    
    if (result != 0) {
        const char* error = mcrypt_strerror(result);
        delete[] cipherText;
        NanThrowError(NanNew<String>(error));
    }

    Local<Object> retVal = NanNewBufferHandle(cipherText, length);
    delete[] cipherText;

    NanReturnValue(retVal);
}

NAN_METHOD(MCrypt::Decrypt) {
    NanScope();
    
    if (args.Length() < 1) {
        NanThrowTypeError("Missing parameter. Plaintext should be specified.");
    }
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());
    
    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int result = 0;
    char* cipherText = {0};
    size_t length = 0;

    if (args[0]->IsString()) {

        NanUtf8String value(args[0]);
        length = value.length();
        cipherText = mcrypt->transform<mdecrypt_generic>(*value, &length, &result);

    } else if (node::Buffer::HasInstance(args[0])) {
        length = node::Buffer::Length(args[0]);
        cipherText = mcrypt->transform<mdecrypt_generic>(node::Buffer::Data(args[0]), &length, &result);

    } else {
        NanThrowTypeError("Ciphertext has got incorrect type. Should be Buffer or String.");
    }
    
    if (result != 0) {
        const char* error = mcrypt_strerror(result);
        delete[] cipherText;
        NanThrowError(NanNew<String>(error));
    }

    Local<Object> retVal = NanNewBufferHandle(cipherText, length);
    delete[] cipherText;

    NanReturnValue(retVal);
}

NAN_METHOD(MCrypt::ValidateKeySize) {
    NanScope();

    if(args.Length() == 0) {
        NanReturnUndefined();
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());
    Local<Boolean> state = args[0]->ToBoolean();
    mcrypt->checkKeySize = state->Value();

    NanReturnUndefined();
}

NAN_METHOD(MCrypt::ValidateIvSize) {
    NanScope();

    if(args.Length() == 0) {
        NanReturnUndefined();
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());
    Local<Boolean> state = args[0]->ToBoolean();
    mcrypt->checkIvSize = state->Value();

    NanReturnUndefined();
}

NAN_METHOD(MCrypt::SelfTest) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_self_test(mcrypt->mcrypt_) == 0) {
        NanReturnValue(NanTrue());
    }

    NanReturnValue(NanFalse());
}

NAN_METHOD(MCrypt::IsBlockAlgorithmMode) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_is_block_algorithm_mode(mcrypt->mcrypt_) == 1) {
        NanReturnValue(NanTrue());
    }
    
    NanReturnValue(NanFalse());
}

NAN_METHOD(MCrypt::IsBlockAlgorithm) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_is_block_algorithm(mcrypt->mcrypt_) == 1) {
        NanReturnValue(NanTrue());
    }
    
    NanReturnValue(NanFalse());
}

NAN_METHOD(MCrypt::IsBlockMode) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_is_block_mode(mcrypt->mcrypt_) == 1) {
        NanReturnValue(NanTrue());
    }
    
    NanReturnValue(NanFalse());
}

NAN_METHOD(MCrypt::GetBlockSize) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int blockSize = mcrypt_enc_get_block_size(mcrypt->mcrypt_);
    
    NanReturnValue(NanNew<Number>(blockSize));
}

NAN_METHOD(MCrypt::GetKeySize) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int keySize = mcrypt_enc_get_key_size(mcrypt->mcrypt_);

    NanReturnValue(NanNew<Number>(keySize));
}

NAN_METHOD(MCrypt::GetSupportedKeySizes) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    std::vector<size_t> keySizes = mcrypt->getKeySizes();

    Local<Array> array = NanNew<Array>(keySizes.size());
    
    for (size_t i = 0; i < keySizes.size(); i++) {
        array->Set(i, NanNew<Number>(keySizes[i]));
    }
    
    NanReturnValue(array);
}

NAN_METHOD(MCrypt::GetIvSize) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int ivSize = mcrypt_enc_get_iv_size(mcrypt->mcrypt_);
    
    NanReturnValue(NanNew<Number>(ivSize));
}

NAN_METHOD(MCrypt::HasIv) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    if (mcrypt_enc_mode_has_iv(mcrypt->mcrypt_) == 1) {
        NanReturnValue(NanTrue());
    }
    
    NanReturnValue(NanFalse());
}

NAN_METHOD(MCrypt::GetAlgorithmName) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    char* name = mcrypt_enc_get_algorithms_name(mcrypt->mcrypt_);
    Local<String> ret = NanNew<String>(name);
    mcrypt_free(name);

    NanReturnValue(ret);
}

NAN_METHOD(MCrypt::GetModeName) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    char* name = mcrypt_enc_get_modes_name(mcrypt->mcrypt_);
    Local<String> ret = NanNew<String>(name);
    mcrypt_free(name);

    NanReturnValue(ret);
}

NAN_METHOD(MCrypt::GenerateIv) {
    NanScope();
    
    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(args.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)
    
    int ivSize = mcrypt_enc_get_iv_size(mcrypt->mcrypt_);
    
    Local<Object> buffer = NanNewBufferHandle(ivSize);
    
    char* iv = node::Buffer::Data(buffer);
    
    while(ivSize) {
        iv[--ivSize] = 255.0 * std::rand() / RAND_MAX;
    }

    NanReturnValue(buffer);
}

NAN_METHOD(MCrypt::GetAlgorithmNames) {
    NanScope();
    
    NanUtf8String path(args[0]);
    
    int size = 0;
    char** algos = mcrypt_list_algorithms(*path, &size);
    
    Local<Array> array = NanNew<Array>(size);
    
    if (array.IsEmpty()) {
        NanReturnValue(NanNew<Array>());
    }
    
    for (int i = 0; i < size; i++) {
        array->Set(i, NanNew<String>(algos[i]));
    }
    
    mcrypt_free_p(algos, size);
    
    NanReturnValue(array);
}

NAN_METHOD(MCrypt::GetModeNames) {
    NanScope();
    
    NanUtf8String path(args[0]);
    
    int size = 0;
    char** modes = mcrypt_list_modes(*path, &size);
    
    Local<Array> array = NanNew<Array>(size);
    
    if (array.IsEmpty())
        NanReturnValue(NanNew<Array>());
    
    for (int i = 0; i < size; i++) {
        array->Set(i, NanNew<String>(modes[i]));
    }
    
    mcrypt_free_p(modes, size);

    NanReturnValue(array);
}

void MCrypt::Init(Handle<Object> exports) {
    NanScope();

    Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);
    tpl->SetClassName(NanNew("MCrypt"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1); 

    // prototype
    NODE_SET_PROTOTYPE_METHOD(tpl, "encrypt", Encrypt);
    NODE_SET_PROTOTYPE_METHOD(tpl, "decrypt", Decrypt);
    NODE_SET_PROTOTYPE_METHOD(tpl, "open", Open);
    NODE_SET_PROTOTYPE_METHOD(tpl, "validateKeySize", ValidateKeySize);
    NODE_SET_PROTOTYPE_METHOD(tpl, "validateIvSize", ValidateIvSize);
    NODE_SET_PROTOTYPE_METHOD(tpl, "selfTest", SelfTest);
    NODE_SET_PROTOTYPE_METHOD(tpl, "isBlockAlgorithmMode", IsBlockAlgorithmMode);
    NODE_SET_PROTOTYPE_METHOD(tpl, "isBlockAlgorithm", IsBlockAlgorithm);
    NODE_SET_PROTOTYPE_METHOD(tpl, "isBlockMode", IsBlockMode);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getBlockSize", GetBlockSize);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getKeySize", GetKeySize);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getSupportedKeySizes", GetSupportedKeySizes);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getIvSize", GetIvSize);
    NODE_SET_PROTOTYPE_METHOD(tpl, "hasIv", HasIv);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getAlgorithmName", GetAlgorithmName);
    NODE_SET_PROTOTYPE_METHOD(tpl, "getModeName", GetModeName);
    NODE_SET_PROTOTYPE_METHOD(tpl, "generateIv", GenerateIv);

    // exports
    NanAssignPersistent(constructor, tpl->GetFunction());
    exports->Set(NanNew("MCrypt"), tpl->GetFunction());
    NODE_SET_METHOD(exports, "getAlgorithmNames", GetAlgorithmNames);
    NODE_SET_METHOD(exports, "getModeNames", GetModeNames);
}

NODE_MODULE(mcrypt, MCrypt::Init)
