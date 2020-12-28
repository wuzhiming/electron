// Copyright (c) 2013 GitHub, Inc.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

#include <string>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <vector>


#include "shell/common/gin_converters/callback_converter.h"
#include "shell/common/gin_converters/file_path_converter.h"
#include "shell/common/gin_converters/gurl_converter.h"
#include "shell/common/gin_helper/dictionary.h"
#include "shell/common/gin_helper/error_thrower.h"
#include "shell/common/node_includes.h"

#include "shell/common/api/xxtea.h"

namespace {
using v8::FunctionCallbackInfo;
void OnOpenFinished(gin_helper::Promise<void> promise,
                    const std::string& error) {
  if (error.empty())
    promise.Resolve();
  else
    promise.RejectWithErrorMessage(error.c_str());
}

v8::Local<v8::Promise> OpenExternal(const GURL& url, gin::Arguments* args) {
  gin_helper::Promise<void> promise(args->isolate());
  v8::Local<v8::Promise> handle = promise.GetHandle();

  platform_util::OpenExternalOptions options;
  if (args->Length() >= 2) {
    gin::Dictionary obj(nullptr);
    if (args->GetNext(&obj)) {
      obj.Get("activate", &options.activate);
      obj.Get("workingDirectory", &options.working_dir);
    }
  }

  platform_util::OpenExternal(
      url, options, base::BindOnce(&OnOpenFinished, std::move(promise)));
  return handle;
}

v8::Local<v8::Promise> OpenPath(v8::Isolate* isolate,
                                const base::FilePath& full_path) {
  gin_helper::Promise<const std::string&> promise(isolate);
  v8::Local<v8::Promise> handle = promise.GetHandle();

  platform_util::OpenPath(
      full_path,
      base::BindOnce(
          [](gin_helper::Promise<const std::string&> promise,
             const std::string& err_msg) { promise.Resolve(err_msg); },
          std::move(promise)));
  return handle;
}

bool MoveItemToTrash(gin::Arguments* args) {
  base::FilePath full_path;
  args->GetNext(&full_path);

  bool delete_on_fail = false;
  args->GetNext(&delete_on_fail);

  return platform_util::MoveItemToTrash(full_path, delete_on_fail);
}

#if defined(OS_WIN)
bool WriteShortcutLink(const base::FilePath& shortcut_path,
                       gin_helper::Arguments* args) {
  base::win::ShortcutOperation operation = base::win::SHORTCUT_CREATE_ALWAYS;
  args->GetNext(&operation);
  gin::Dictionary options = gin::Dictionary::CreateEmpty(args->isolate());
  if (!args->GetNext(&options)) {
    args->ThrowError();
    return false;
  }

  base::win::ShortcutProperties properties;
  base::FilePath path;
  base::string16 str;
  int index;
  if (options.Get("target", &path))
    properties.set_target(path);
  if (options.Get("cwd", &path))
    properties.set_working_dir(path);
  if (options.Get("args", &str))
    properties.set_arguments(str);
  if (options.Get("description", &str))
    properties.set_description(str);
  if (options.Get("icon", &path) && options.Get("iconIndex", &index))
    properties.set_icon(path, index);
  if (options.Get("appUserModelId", &str))
    properties.set_app_id(str);

  base::win::ScopedCOMInitializer com_initializer;
  return base::win::CreateOrUpdateShortcutLink(shortcut_path, properties,
                                               operation);
}

v8::Local<v8::Value> ReadShortcutLink(gin_helper::ErrorThrower thrower,
                                      const base::FilePath& path) {
  using base::win::ShortcutProperties;
  gin::Dictionary options = gin::Dictionary::CreateEmpty(thrower.isolate());
  base::win::ScopedCOMInitializer com_initializer;
  base::win::ShortcutProperties properties;
  if (!base::win::ResolveShortcutProperties(
          path, ShortcutProperties::PROPERTIES_ALL, &properties)) {
    thrower.ThrowError("Failed to read shortcut link");
    return v8::Null(thrower.isolate());
  }
  options.Set("target", properties.target);
  options.Set("cwd", properties.working_dir);
  options.Set("args", properties.arguments);
  options.Set("description", properties.description);
  options.Set("icon", properties.icon);
  options.Set("iconIndex", properties.icon_index);
  options.Set("appUserModelId", properties.app_id);
  return gin::ConvertToV8(thrower.isolate(), options);
}
#endif
const char* ENCRYPT_KEY = "YDDAD_RUOY_SOHW";

// read file from path
std::vector<uint8_t> ReadFileIntoString(const char* filename) {
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

const char* DecryptScript(string path) {
  std::vector<uint8_t>&& content = ReadFileIntoString(path.c_str());
  // std::cout << "content " << content.size() << std::endl;
  size_t len = content.size();
  auto decryp_data = xxtea_decrypt(content.data(), len, ENCRYPT_KEY, &len);
  return (const char*)decryp_data;
}
void compileFunction(const std::string& file_path, gin_helper::Arguments* args){
  // get current isolate
  Isolate* isolate = args->isolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  // get jsc absolute path
  string filePath = file_path;
  // std::cout << "filePath " << filePath << std::endl;
  // decrypt content
  const char* content = DecryptScript(filePath);
  // printf("out is %s\n", content);

  auto scriptContent =
      String::NewFromUtf8(isolate, content, NewStringType::kNormal)
          .ToLocalChecked();
  free(&content);

  Local<v8::Object> global = context->Global();
  Local<v8::Value> value =
      String::NewFromUtf8(isolate, "__vm__", NewStringType::kNormal)
          .ToLocalChecked();
  Local<v8::Value> vmValue = global->Get(context, value).ToLocalChecked();

  if (!vmValue->IsObject())
    return;

  Local<v8::Object> vmObject = vmValue->ToObject(context).ToLocalChecked();

  v8::TryCatch tryCatch(isolate);
  auto compileFunctionKey =
      String::NewFromUtf8(isolate, "compileFunction", NewStringType::kNormal)
          .ToLocalChecked();
  if (!vmObject->Has(context, compileFunctionKey).FromJust())
    return;
  Local<Value> params[3] = {scriptContent, args[1], args[2]};
  v8::Local<v8::Function> func = vmObject->Get(context, compileFunctionKey)
                                     .ToLocalChecked()
                                     .As<v8::Function>();
  Local<Value> ret = func->Call(context, vmObject, 3, params).ToLocalChecked();

  if (tryCatch.HasCaught() || tryCatch.HasTerminated()) {
    v8::Local<v8::Value> exception = tryCatch.Exception();
    v8::Local<v8::String> msg = exception->ToString(context).ToLocalChecked();
    std::string msgCPP = *v8::String::Utf8Value(isolate, msg);
    std::cout << "Error " << msgCPP << std::endl;
  }

  args.GetReturnValue().Set(ret);
}
void Initialize(v8::Local<v8::Object> exports,
                v8::Local<v8::Value> unused,
                v8::Local<v8::Context> context,
                void* priv) {
  gin_helper::Dictionary dict(context->GetIsolate(), exports);
  dict.SetMethod("test", &compileFunction);
}

}  // namespace

NODE_LINKED_MODULE_CONTEXT_AWARE(electron_common_compile, Initialize)
