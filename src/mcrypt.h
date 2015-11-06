
#ifndef SRC_NODE_MCRYPT_H_
#define SRC_NODE_MCRYPT_H_

#include <vector> 
#include <algorithm> 
#include <sstream>

#include <nan.h>
#include <mcrypt.h>

#define MCRYPT_MODULE_ERROR_CHECK(mcrypt) \
    if (mcrypt->mcrypt_ == MCRYPT_FAILED) { \
        Nan::ThrowError("MCrypt module could not open"); \
    }

using namespace v8;

class MCrypt : public node::ObjectWrap {
    public:
        static void Init(Handle<Object> exports);
    
    private:
        MCrypt(Nan::NAN_METHOD_ARGS_TYPE args);
        ~MCrypt();
        
        template <int (*modify)(MCRYPT, void *, int)>
        char* transform(const char* plainText, size_t* length, int* result);

        std::vector<size_t> getKeySizes();
        
        static Nan::Persistent<Function> constructor;

        static NAN_METHOD(New);
        static NAN_METHOD(Encrypt);
        static NAN_METHOD(Decrypt);
        static NAN_METHOD(Open);
        static NAN_METHOD(ValidateKeySize);
        static NAN_METHOD(ValidateIvSize);
        static NAN_METHOD(SelfTest);
        static NAN_METHOD(IsBlockAlgorithmMode);
        static NAN_METHOD(IsBlockAlgorithm);
        static NAN_METHOD(IsBlockMode);
        static NAN_METHOD(GetBlockSize);
        static NAN_METHOD(GetKeySize);
        static NAN_METHOD(GetSupportedKeySizes);
        static NAN_METHOD(GetIvSize);
        static NAN_METHOD(HasIv);
        static NAN_METHOD(GetAlgorithmName);
        static NAN_METHOD(GetModeName);
        static NAN_METHOD(GenerateIv);
        static NAN_METHOD(Close);

        static NAN_METHOD(GetAlgorithmNames);
        static NAN_METHOD(GetModeNames);
        
        MCRYPT mcrypt_;
        std::string key;
        std::string iv;

        bool checkKeySize;
        bool checkIvSize;
        
        Nan::Utf8String algo;
        Nan::Utf8String mode;
};

#endif  // ~ SRC_NODE_MCRYPT_H_
