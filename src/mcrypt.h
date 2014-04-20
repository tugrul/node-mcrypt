
#ifndef SRC_NODE_MCRYPT_H_
#define SRC_NODE_MCRYPT_H_

#include <node.h>
#include <mcrypt.h>

class MCrypt : public node::ObjectWrap {
    public:
        static void Init(v8::Handle<v8::Object> exports);
    
    private:
        MCrypt();
        ~MCrypt();
        
        static v8::Persistent<v8::Function> constructor;
        
        static v8::Handle<v8::Value> New(const v8::Arguments& args);
        
        static v8::Handle<v8::Value> Encrypt(const v8::Arguments& args);
        static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);
        static v8::Handle<v8::Value> Open(const v8::Arguments& args);
        static v8::Handle<v8::Value> ValidateKeySize(const v8::Arguments& args);
        static v8::Handle<v8::Value> ValidateIvSize(const v8::Arguments& args);
        static v8::Handle<v8::Value> SelfTest(const v8::Arguments& args);
        static v8::Handle<v8::Value> IsBlockAlgorithmMode(const v8::Arguments& args);
        static v8::Handle<v8::Value> IsBlockAlgorithm(const v8::Arguments& args);
        static v8::Handle<v8::Value> IsBlockMode(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetBlockSize(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetKeySize(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetSupportedKeySizes(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetIvSize(const v8::Arguments& args);
        static v8::Handle<v8::Value> HasIv(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetAlgorithmName(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetModeName(const v8::Arguments& args);
        static v8::Handle<v8::Value> GenerateIv(const v8::Arguments& args);
        static v8::Handle<v8::Value> Close(const v8::Arguments& args);
        
        static v8::Handle<v8::Value> GetAlgorithmNames(const v8::Arguments& args);
        static v8::Handle<v8::Value> GetModeNames(const v8::Arguments& args);
        
        MCRYPT mcrypt_;
        char* key;
        int keyLen;
        char* iv;
        bool checkKeySize;
        bool checkIvSize;
};

#endif  // ~ SRC_NODE_MCRYPT_H_
