

#include "mcrypt.h"

using namespace v8;

Nan::Persistent<Function> MCrypt::constructor;

MCrypt::MCrypt(Nan::NAN_METHOD_ARGS_TYPE info):
    checkKeySize(true),
    checkIvSize(true),
    algo(info[0]),
    mode(info[1]) {

    mcrypt_ = mcrypt_module_open(*algo, *mode);
};

MCrypt::~MCrypt() {
    mcrypt_module_close(mcrypt_);
};


template <int (*modify)(MCRYPT mcrypt, void* target, int length)>
char* MCrypt::transform(const char* plainText, size_t* length, int* result) {
    const size_t origLength = *length;

    // a block algorithm works on whole blocks: the length goes up to the
    // next multiple of the block size and the rest is zero bytes.
    // an empty input stays empty
    if (mcrypt_enc_is_block_algorithm(mcrypt_) == 1) {
        size_t blockSize = mcrypt_enc_get_block_size(mcrypt_);
        *length = ((*length + blockSize - 1) / blockSize) * blockSize;
    }

    char* targetData = new char[*length]();
    std::copy(plainText, plainText + origLength, targetData);

    // libmcrypt reads as many bytes of iv as the mode uses, however many
    // open() was given. a shorter iv is filled up with zero bytes, which is
    // also what libmcrypt takes when it gets no iv
    std::string ivBuf(iv);
    const int ivSize = mcrypt_enc_get_iv_size(mcrypt_);

    if (ivSize > 0 && ivBuf.length() < (size_t)ivSize) {
        ivBuf.resize(ivSize, '\0');
    }

    if ((*result = mcrypt_generic_init(mcrypt_, key.data(), key.length(), ivBuf.data())) < 0) {
        return targetData;
    }

    if ((*result = modify(mcrypt_, targetData, *length)) != 0) {
        mcrypt_generic_deinit(mcrypt_);
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

    if (!info.IsConstructCall()) {
        Local<Value> argv[] = {info[0], info[1]};
        Local<Function> cons = Nan::New<Function>(constructor);
        Nan::MaybeLocal<Object> instance = Nan::NewInstance(cons, 2, argv);

        // empty when the constructor threw. the exception is already set
        if (instance.IsEmpty()) {
            return;
        }

        return info.GetReturnValue().Set(instance.ToLocalChecked());
    }

    if (info.Length() < 2) {
        return Nan::ThrowTypeError("Missing parameters. Algorithm and mode should be specified.");
    }

    MCrypt* mcrypt = new MCrypt(info);

    if (mcrypt->mcrypt_ == MCRYPT_FAILED) {
        delete mcrypt;
        return Nan::ThrowError("MCrypt module could not open");
    }

    mcrypt->Wrap(info.This());

    return info.GetReturnValue().Set(info.This());
}

NAN_METHOD(MCrypt::Open) {

    if (info.Length() < 1) {
        return Nan::ThrowTypeError("Missing parameter. Key should be specified.");
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (info[0]->IsString()) {
        Nan::Utf8String value(info[0]);

        mcrypt->key = std::string(*value, value.length());

    } else if (node::Buffer::HasInstance(info[0])) {

        mcrypt->key = std::string(node::Buffer::Data(info[0]), node::Buffer::Length(info[0]));

    } else {
        return Nan::ThrowTypeError("Key has got incorrect type. Should be Buffer or String.");
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
                return Nan::ThrowTypeError(error.c_str());
            }
        }
    }

    if (info[1]->IsUndefined()) {
        return info.GetReturnValue().SetUndefined();
    }

    size_t ivLen = 0;

    if (info[1]->IsString()) {

        Nan::Utf8String value(info[1]);

        ivLen = value.length();
        mcrypt->iv = std::string(*value, ivLen);

    } else if (node::Buffer::HasInstance(info[1])) {

        ivLen = node::Buffer::Length(info[1]);
        mcrypt->iv = std::string(node::Buffer::Data(info[1]), ivLen);
    } else {
        return Nan::ThrowTypeError("Iv has got incorrect type. Should be Buffer or String.");
    }

    if (mcrypt->checkIvSize) {
        if ((size_t)mcrypt_enc_get_iv_size(mcrypt->mcrypt_) != ivLen) {
            return Nan::ThrowTypeError("Invalid iv size. You can determine iv size using getIvSize()");
        }
    }

    return info.GetReturnValue().SetUndefined();
}

// Callback function passed to Nan::NewBuffer()
static void freeCipherText(char *cipherText, void *hint) {
    delete[] cipherText;
}

NAN_METHOD(MCrypt::Encrypt) {

    if (info.Length() < 1) {
        return Nan::ThrowTypeError("Missing parameter. Plaintext should be specified.");
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    int result = 0;
    char* cipherText = {0};
    size_t length = 0;

    if (info[0]->IsString()) {

        Nan::Utf8String value(info[0]);
        length = value.length();
        cipherText = mcrypt->transform<mcrypt_generic>(*value, &length, &result);

    } else if(node::Buffer::HasInstance(info[0])) {

        length = node::Buffer::Length(info[0]);
        cipherText = mcrypt->transform<mcrypt_generic>(node::Buffer::Data(info[0]), &length, &result);

    } else {
        return Nan::ThrowTypeError("Plaintext has got incorrect type. Should be Buffer or String.");
    }

    if (result != 0) {
        const char* error = mcrypt_strerror(result);
        delete[] cipherText;
        return Nan::ThrowError(error);
    }

    return info.GetReturnValue().Set(Nan::NewBuffer(cipherText, length, freeCipherText, 0).ToLocalChecked());
}

NAN_METHOD(MCrypt::Decrypt) {

    if (info.Length() < 1) {
        return Nan::ThrowTypeError("Missing parameter. Ciphertext should be specified.");
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    int result = 0;
    char* cipherText = {0};
    size_t length = 0;

    if (info[0]->IsString()) {

        Nan::Utf8String value(info[0]);
        length = value.length();
        cipherText = mcrypt->transform<mdecrypt_generic>(*value, &length, &result);

    } else if (node::Buffer::HasInstance(info[0])) {
        length = node::Buffer::Length(info[0]);
        cipherText = mcrypt->transform<mdecrypt_generic>(node::Buffer::Data(info[0]), &length, &result);

    } else {
        return Nan::ThrowTypeError("Ciphertext has got incorrect type. Should be Buffer or String.");
    }

    if (result != 0) {
        const char* error = mcrypt_strerror(result);
        delete[] cipherText;
        return Nan::ThrowError(error);
    }

    return info.GetReturnValue().Set(Nan::NewBuffer(cipherText, length, freeCipherText, 0).ToLocalChecked());
}

NAN_METHOD(MCrypt::ValidateKeySize) {

    if(info.Length() == 0) {
        return info.GetReturnValue().SetUndefined();
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());
    mcrypt->checkKeySize = Nan::Equals(info[0], Nan::True()).FromJust();

    return info.GetReturnValue().SetUndefined();
}

NAN_METHOD(MCrypt::ValidateIvSize) {

    if(info.Length() == 0) {
        return info.GetReturnValue().SetUndefined();
    }

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());
    mcrypt->checkIvSize = Nan::Equals(info[0], Nan::True()).FromJust();

    return info.GetReturnValue().SetUndefined();
}

NAN_METHOD(MCrypt::SelfTest) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_self_test(mcrypt->mcrypt_) == 0) {
        return info.GetReturnValue().Set(Nan::True());
    }

    return info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::IsBlockAlgorithmMode) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_is_block_algorithm_mode(mcrypt->mcrypt_) == 1) {
        return info.GetReturnValue().Set(Nan::True());
    }

    return info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::IsBlockAlgorithm) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_is_block_algorithm(mcrypt->mcrypt_) == 1) {
        return info.GetReturnValue().Set(Nan::True());
    }

    return info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::IsBlockMode) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_is_block_mode(mcrypt->mcrypt_) == 1) {
        return info.GetReturnValue().Set(Nan::True());
    }

    return info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::GetBlockSize) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    int blockSize = mcrypt_enc_get_block_size(mcrypt->mcrypt_);

    return info.GetReturnValue().Set(Nan::New<Number>(blockSize));
}

NAN_METHOD(MCrypt::GetKeySize) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    int keySize = mcrypt_enc_get_key_size(mcrypt->mcrypt_);

    return info.GetReturnValue().Set(Nan::New<Number>(keySize));
}

NAN_METHOD(MCrypt::GetSupportedKeySizes) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    std::vector<size_t> keySizes = mcrypt->getKeySizes();

    Local<Array> array = Nan::New<Array>(keySizes.size());

    for (size_t i = 0; i < keySizes.size(); i++) {
	Nan::Set(array, i, Nan::New<Number>(keySizes[i]));
    }

    return info.GetReturnValue().Set(array);
}

NAN_METHOD(MCrypt::GetIvSize) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    int ivSize = mcrypt_enc_get_iv_size(mcrypt->mcrypt_);

    return info.GetReturnValue().Set(Nan::New<Number>(ivSize));
}

NAN_METHOD(MCrypt::HasIv) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    if (mcrypt_enc_mode_has_iv(mcrypt->mcrypt_) == 1) {
        return info.GetReturnValue().Set(Nan::True());
    }

    return info.GetReturnValue().Set(Nan::False());
}

NAN_METHOD(MCrypt::GetAlgorithmName) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    char* name = mcrypt_enc_get_algorithms_name(mcrypt->mcrypt_);
    Local<String> value = Nan::New<String>(name).ToLocalChecked();

    mcrypt_free(name);

    return info.GetReturnValue().Set(value);
}

NAN_METHOD(MCrypt::GetModeName) {

    MCrypt* mcrypt = ObjectWrap::Unwrap<MCrypt>(info.This());

    MCRYPT_MODULE_ERROR_CHECK(mcrypt)

    char* name = mcrypt_enc_get_modes_name(mcrypt->mcrypt_);
    Local<String> value = Nan::New<String>(name).ToLocalChecked();

    mcrypt_free(name);

    return info.GetReturnValue().Set(value);
}

NAN_METHOD(MCrypt::GetAlgorithmNames) {

    int size = 0;
    char** algos = mcrypt_list_algorithms(&size);

    Local<Array> array = Nan::New<Array>(size);

    if (array.IsEmpty()) {
        return info.GetReturnValue().Set(Nan::New<Array>());
    }

    for (uint32_t i = 0; i < (uint32_t)size; i++) {
	Nan::Set(array, i, Nan::New<String>(algos[i]).ToLocalChecked());
    }

    mcrypt_free_p(algos, size);

    return info.GetReturnValue().Set(array);
}

NAN_METHOD(MCrypt::GetModeNames) {

    int size = 0;
    char** modes = mcrypt_list_modes(&size);

    Local<Array> array = Nan::New<Array>(size);

    if (array.IsEmpty())
        return info.GetReturnValue().Set(Nan::New<Array>());

    for (uint32_t i = 0; i < (uint32_t)size; i++) {
	Nan::Set(array, i, Nan::New<String>(modes[i]).ToLocalChecked());
    }

    mcrypt_free_p(modes, size);

    return info.GetReturnValue().Set(array);
}

void MCrypt::Init(Local<Object> exports) {

    Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
    tpl->SetClassName(Nan::New("MCrypt").ToLocalChecked());
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    // prototype
    Nan::SetPrototypeMethod(tpl, "encrypt", Encrypt);
    Nan::SetPrototypeMethod(tpl, "decrypt", Decrypt);
    Nan::SetPrototypeMethod(tpl, "open", Open);
    Nan::SetPrototypeMethod(tpl, "validateKeySize", ValidateKeySize);
    Nan::SetPrototypeMethod(tpl, "validateIvSize", ValidateIvSize);
    Nan::SetPrototypeMethod(tpl, "selfTest", SelfTest);
    Nan::SetPrototypeMethod(tpl, "isBlockAlgorithmMode", IsBlockAlgorithmMode);
    Nan::SetPrototypeMethod(tpl, "isBlockAlgorithm", IsBlockAlgorithm);
    Nan::SetPrototypeMethod(tpl, "isBlockMode", IsBlockMode);
    Nan::SetPrototypeMethod(tpl, "getBlockSize", GetBlockSize);
    Nan::SetPrototypeMethod(tpl, "getKeySize", GetKeySize);
    Nan::SetPrototypeMethod(tpl, "getSupportedKeySizes", GetSupportedKeySizes);
    Nan::SetPrototypeMethod(tpl, "getIvSize", GetIvSize);
    Nan::SetPrototypeMethod(tpl, "hasIv", HasIv);
    Nan::SetPrototypeMethod(tpl, "getAlgorithmName", GetAlgorithmName);
    Nan::SetPrototypeMethod(tpl, "getModeName", GetModeName);

    // exports
    constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
    Nan::Set(exports, Nan::New("MCrypt").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
    Nan::SetMethod(exports, "getAlgorithmNames", GetAlgorithmNames);
    Nan::SetMethod(exports, "getModeNames", GetModeNames);
}

NODE_MODULE(mcrypt, MCrypt::Init)
