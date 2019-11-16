#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>

extern "C" {

#include "../util/sys_defs.h"

#include "../global/quote_822_local.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  FuzzedDataProvider provider(Data, Size);
  VSTRING *int_address = vstring_alloc(100);
  std::string input = provider.ConsumeRemainingBytesAsString();
  unquote_822_local(int_address, input.c_str());
  vstring_free(int_address);
  return 0;
}
}
