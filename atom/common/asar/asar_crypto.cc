    
#include "atom/common/asar/asar_crypto.h"

#include <cstring>
#include <cassert>

#define ALGORITHM "rc4"
#define PASSWORD "filr-ball-electron-2015"

namespace asar {

bool CipherBase::DecryptData(char *indata, int inlen) {

  asar::CipherBase *decrypt = CipherBase::CreateDecipher();
  bool ret = decrypt->Update(indata, inlen, true);
  delete decrypt;

  return ret;
}

CipherBase* CipherBase::CreateDecipher() {
  asar::CipherBase *decrypt = new asar::CipherBase(asar::CipherBase::kDecipher);
  decrypt->Init(ALGORITHM, PASSWORD, strlen(PASSWORD));

  return decrypt;
}

bool CipherBase::Update(char *indata, int inlen, bool invoke_final) {
  // invoke internal Update()

  unsigned char* update_out = nullptr;
  bool r = false;
  int update_out_len = 0;
 
  r = Update(indata, inlen, &update_out, &update_out_len);
  if (!r) {
    delete[] update_out;
    printf("Failed to update data: return value is false");
    return false;
  }

  if (update_out == nullptr || update_out_len == 0) {
     printf("Failed to update data: update_out is null or out_len is 0");;
    return false;
  }

  // invoke data decrypted by Update()
  memcpy(indata, update_out, update_out_len);
  delete[] update_out;

  // invoke internal final()
  if (invoke_final) {
    unsigned char* final_out = nullptr;
    int final_out_len = 0;
    r = Final(&final_out, &final_out_len);
    if (final_out_len <= 0 || !r) {
      delete[] final_out;
      final_out = nullptr;
      final_out_len = 0;
      if (!r) {
        printf("Failed to invoke cipher.Final()");
        return false;
      }
    }

    if (final_out_len > 0)
      memcpy(indata + update_out_len, final_out, final_out_len);

    delete[] final_out;
  }

  return true;
}

void CipherBase::Init(const char* cipher_type,
                      const char* key_buf,
                      int key_buf_len) {
  // HandleScope scope(env()->isolate());

  //CHECK_EQ(cipher_, nullptr);
  assert(cipher_ == nullptr);
  cipher_ = EVP_get_cipherbyname(cipher_type);
  if (cipher_ == nullptr) {
    // return env()->ThrowError("Unknown cipher");
    printf("Unknown cipher");
    return;
  }

  unsigned char key[EVP_MAX_KEY_LENGTH];
  unsigned char iv[EVP_MAX_IV_LENGTH];

  int key_len = EVP_BytesToKey(cipher_,
                               EVP_md5(),
                               nullptr,
                               reinterpret_cast<const unsigned char*>(key_buf),
                               key_buf_len,
                               1,
                               key,
                               iv);

  EVP_CIPHER_CTX_init(&ctx_);
  const bool encrypt = (kind_ == kCipher);
  EVP_CipherInit_ex(&ctx_, cipher_, nullptr, nullptr, nullptr, encrypt);
  if (!EVP_CIPHER_CTX_set_key_length(&ctx_, key_len)) {
    EVP_CIPHER_CTX_cleanup(&ctx_);
    // return env()->ThrowError("Invalid key length");
    printf("Invalid key length");
    return;
  }

  EVP_CipherInit_ex(&ctx_,
                    nullptr,
                    nullptr,
                    reinterpret_cast<unsigned char*>(key),
                    reinterpret_cast<unsigned char*>(iv),
                    kind_ == kCipher);
  initialised_ = true;
}

void CipherBase::InitIv(const char* cipher_type,
                        const char* key,
                        int key_len,
                        const char* iv,
                        int iv_len) {

  cipher_ = EVP_get_cipherbyname(cipher_type);
  if (cipher_ == nullptr) {
    // return env()->ThrowError("Unknown cipher");
    printf("Unknown cipher");
    return;
  }

  /* OpenSSL versions up to 0.9.8l failed to return the correct
     iv_length (0) for ECB ciphers */
  if ((int)EVP_CIPHER_iv_length(cipher_) != iv_len &&
      !(EVP_CIPHER_mode(cipher_) == EVP_CIPH_ECB_MODE && iv_len == 0)) {
    // return env()->ThrowError("Invalid IV length");
    printf("Invalid IV length");
    return;
  }
  EVP_CIPHER_CTX_init(&ctx_);
  const bool encrypt = (kind_ == kCipher);
  EVP_CipherInit_ex(&ctx_, cipher_, nullptr, nullptr, nullptr, encrypt);
  if (!EVP_CIPHER_CTX_set_key_length(&ctx_, key_len)) {
    EVP_CIPHER_CTX_cleanup(&ctx_);
    // return env()->ThrowError("Invalid key length");
  }

  EVP_CipherInit_ex(&ctx_,
                    nullptr,
                    nullptr,
                    reinterpret_cast<const unsigned char*>(key),
                    reinterpret_cast<const unsigned char*>(iv),
                    kind_ == kCipher);
  initialised_ = true;
}


bool CipherBase::IsAuthenticatedMode() const {
  // check if this cipher operates in an AEAD mode that we support.
  if (!cipher_)
    return false;
  int mode = EVP_CIPHER_mode(cipher_);
  return mode == EVP_CIPH_GCM_MODE;
}


bool CipherBase::GetAuthTag(char** out, unsigned int* out_len) const {
  // only callable after Final and if encrypting.
  if (initialised_ || kind_ != kCipher || !auth_tag_)
    return false;
  *out_len = auth_tag_len_;
  *out = static_cast<char*>(malloc(auth_tag_len_));
  //CHECK_NE(*out, nullptr);
  assert(*out != nullptr);
  memcpy(*out, auth_tag_, auth_tag_len_);
  return true;
}

bool CipherBase::SetAuthTag(const char* data, unsigned int len) {
  if (!initialised_ || !IsAuthenticatedMode() || kind_ != kDecipher)
    return false;
  delete[] auth_tag_;
  auth_tag_len_ = len;
  auth_tag_ = new char[len];
  memcpy(auth_tag_, data, len);
  return true;
}


bool CipherBase::SetAAD(const char* data, unsigned int len) {
  if (!initialised_ || !IsAuthenticatedMode())
    return false;
  int outlen;
  if (!EVP_CipherUpdate(&ctx_,
                        nullptr,
                        &outlen,
                        reinterpret_cast<const unsigned char*>(data),
                        len)) {
    return false;
  }
  return true;
}

bool CipherBase::Update(const char* data,
                        int len,
                        unsigned char** out,
                        int* out_len) {
  if (!initialised_)
    return 0;

  // on first update:
  if (kind_ == kDecipher && IsAuthenticatedMode() && auth_tag_ != nullptr) {
    EVP_CIPHER_CTX_ctrl(&ctx_,
                        EVP_CTRL_GCM_SET_TAG,
                        auth_tag_len_,
                        reinterpret_cast<unsigned char*>(auth_tag_));
    delete[] auth_tag_;
    auth_tag_ = nullptr;
  }

  *out_len = len + EVP_CIPHER_CTX_block_size(&ctx_);
  *out = new unsigned char[*out_len];
  return EVP_CipherUpdate(&ctx_,
                          *out,
                          out_len,
                          reinterpret_cast<const unsigned char*>(data),
                          len);
}


bool CipherBase::SetAutoPadding(bool auto_padding) {
  if (!initialised_)
    return false;
  return EVP_CIPHER_CTX_set_padding(&ctx_, auto_padding);
}

bool CipherBase::Final(unsigned char** out, int *out_len) {
  if (!initialised_)
    return false;

  *out = new unsigned char[EVP_CIPHER_CTX_block_size(&ctx_)];
  int r = EVP_CipherFinal_ex(&ctx_, *out, out_len);

  if (r && kind_ == kCipher) {
    delete[] auth_tag_;
    auth_tag_ = nullptr;
    if (IsAuthenticatedMode()) {
      auth_tag_len_ = EVP_GCM_TLS_TAG_LEN;  // use default tag length
      auth_tag_ = new char[auth_tag_len_];
      memset(auth_tag_, 0, auth_tag_len_);
      EVP_CIPHER_CTX_ctrl(&ctx_,
                          EVP_CTRL_GCM_GET_TAG,
                          auth_tag_len_,
                          reinterpret_cast<unsigned char*>(auth_tag_));
    }
  }

  EVP_CIPHER_CTX_cleanup(&ctx_);
  initialised_ = false;

  return r == 1;
}

} // end of namespace asar