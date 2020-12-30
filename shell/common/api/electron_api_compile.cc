// Copyright (c) 2013 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "shell/common/gin_converters/callback_converter.h"
#include "shell/common/gin_converters/file_path_converter.h"
#include "shell/common/gin_converters/gurl_converter.h"
#include "shell/common/gin_helper/dictionary.h"
#include "shell/common/gin_helper/error_thrower.h"
#include "shell/common/node_includes.h"

#include "shell/common/api/xxtea.h"

namespace {
using namespace v8;
const char* ENCRYPT_KEY = "YDDAD_RUOY_SOHW";

// read file from path
std::vector<uint8_t> ReadFile(const char* filename) {
  FILE* fp = fopen(filename, "rb");
  std::vector<uint8_t> output;
  char buff[1024];
  int readn = 0;
  while ((readn = fread(buff, 1, sizeof(buff), fp)) > 0) {
    output.insert(output.end(), buff, buff + readn);
  }
  if (readn < 0) {
    // error
    std::cerr << "ERROR IN READING..." << std::endl;
  }
  fclose(fp);
  return output;
}

const char* DecryptScript(std::string path) {
  std::vector<uint8_t>&& content = ReadFile(path.c_str());
  // std::cout << "content " << content.size() << std::endl;
  size_t len = content.size();
  void* decryp_data = xxtea_decrypt(content.data(), len, ENCRYPT_KEY, &len);
  return (const char*)decryp_data;
}
v8::Local<Value> compileFunction(v8::Isolate* isolate,
                                 const std::string& file_path,
                                 v8::Local<Value> param1,
                                 v8::Local<Value> param2) {
  // get current isolate
  v8::Local<Value> ret;
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  // get jsc absolute path
  std::string filePath = file_path;
  // std::cout << "filePath " << filePath << std::endl;
  // decrypt content
  const char* content = DecryptScript(filePath);
  // printf("out is %s\n", content);

  auto scriptContent =
      v8::String::NewFromUtf8(isolate, content, NewStringType::kNormal)
          .ToLocalChecked();
  free(&content);

  v8::Local<v8::Object> global = context->Global();
  v8::Local<v8::Value> value =
      String::NewFromUtf8(isolate, "__vm__", NewStringType::kNormal)
          .ToLocalChecked();
  v8::Local<v8::Value> vmValue = global->Get(context, value).ToLocalChecked();

  if (!vmValue->IsObject())
    return ret;

  v8::Local<v8::Object> vmObject = vmValue->ToObject(context).ToLocalChecked();

  v8::TryCatch tryCatch(isolate);
  auto compileFunctionKey = v8::String::NewFromUtf8(isolate, "compileFunction",
                                                    NewStringType::kNormal)
                                .ToLocalChecked();
  if (!vmObject->Has(context, compileFunctionKey).FromJust())
    return ret;

  v8::Local<Value> params[3] = {scriptContent, param1, param2};
  v8::Local<v8::Function> func = vmObject->Get(context, compileFunctionKey)
                                     .ToLocalChecked()
                                     .As<v8::Function>();
  ret = func->Call(context, vmObject, 3, params).ToLocalChecked();

  if (tryCatch.HasCaught() || tryCatch.HasTerminated()) {
    v8::Local<v8::Value> exception = tryCatch.Exception();
    v8::Local<v8::String> msg = exception->ToString(context).ToLocalChecked();
    std::string msgCPP = *v8::String::Utf8Value(isolate, msg);
    std::cout << "Error " << msgCPP << std::endl;
  }

  return ret;
}

v8::Local<v8::ArrayBuffer> decryptTea(v8::Isolate* isolate,
                                      const std::string& file_path) {
  // get jsc absolute path
  std::string filePath = file_path;
  // std::cout << "filePath " << filePath << std::endl;
  // decrypt content
  std::vector<uint8_t>&& content = ReadFile(filePath.c_str());
  // std::cout << "content " << content.size() << std::endl;

  size_t len = content.size();
  void* decryp_data = xxtea_decrypt(content.data(), len, ENCRYPT_KEY, &len);

  v8::Local<v8::ArrayBuffer> obj = v8::ArrayBuffer::New(isolate, len);
  memcpy(obj->GetContents().Data(), decryp_data, len);
  return obj;
}

void Initialize(v8::Local<v8::Object> exports,
                v8::Local<v8::Value> unused,
                v8::Local<v8::Context> context,
                void* priv) {
  gin_helper::Dictionary dict(context->GetIsolate(), exports);
  dict.SetMethod("test", &compileFunction);
  dict.SetMethod("test2", &decryptTea);
}

}  // namespace

NODE_LINKED_MODULE_CONTEXT_AWARE(electron_common_compile, Initialize)
