#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>

extern "C" {

#include "../global/mail_addr_crunch.h"
#include "../util/sys_defs.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider provider(Data, Size);
  int in_form = provider.ConsumeBool() ? MA_FORM_INTERNAL : MA_FORM_EXTERNAL;
  int out_form = provider.ConsumeBool() ? MA_FORM_INTERNAL : MA_FORM_EXTERNAL;
  std::string extension("");
  if (provider.ConsumeBool()) {
    extension = provider.ConsumeRandomLengthString(128);
  }
  std::string input = provider.ConsumeRemainingBytesAsString();
  ARGV *result = mail_addr_crunch_opt(
      input.c_str(), extension.size() ? extension.c_str() : nullptr, in_form,
      out_form);
  if (result) {
    argv_free(result);
  }
  return 0;
}
}
