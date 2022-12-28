/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/kernel/xam/apps/xgi_app.h"

#include "xenia/base/logging.h"
#include "xenia/base/threading.h"

#ifdef XE_PLATFORM_WIN32
// NOTE: must be included last as it expects windows.h to already be included.
#define _WINSOCK_DEPRECATED_NO_WARNINGS  // inet_addr
#include <winsock2.h>                    // NOLINT(build/include_order)
#endif

namespace xe {
namespace kernel {
namespace xam {
namespace apps {

XgiApp::XgiApp(KernelState* kernel_state) : App(kernel_state, 0xFB) {}

// http://mb.mirage.org/bugzilla/xliveless/main.c

// TODO: Move these structs.

typedef struct {
  uint8_t ab[8];
} XNKID;

typedef struct {
  uint8_t ab[16];
} XNKEY;

typedef struct {
  // FYI: IN_ADDR should be in network-byte order.
  in_addr ina;                   // IP address (zero if not static/DHCP)
  in_addr inaOnline;             // Online IP address (zero if not online)
  xe::be<uint16_t> wPortOnline;  // Online port
  uint8_t abEnet[6];             // Ethernet MAC address
  uint8_t abOnline[20];          // Online identification
} XNADDR;

struct XSESSION_INFO {
  XNKID sessionID;
  XNADDR hostAddress;
  XNKEY keyExchangeKey;
};  // size 60

struct XUSER_DATA {
  uint8_t type;

  union {
    xe::be<uint32_t> dword_data;      // XUSER_DATA_TYPE_INT32
    LONGLONG qword_data;  // XUSER_DATA_TYPE_INT64
    xe::be<double> double_data;  // XUSER_DATA_TYPE_DOUBLE
    struct             // XUSER_DATA_TYPE_UNICODE
    {
      xe::be<uint32_t> string_length;
      xe::be<uint32_t> string_ptr;
    } string;
    xe::be<float> float_data;
    struct
    {
      xe::be<uint32_t> data_length;
      xe::be<uint32_t> data_ptr;
    } binary;
    FILETIME filetime_data;
  };
};

struct XUSER_PROPERTY {
  xe::be<uint32_t> property_id;
  XUSER_DATA value;
};

struct XUSER_CONTEXT {
  xe::be<uint32_t> context_id;
  xe::be<uint32_t> value;
};

struct XSESSION_SEARCHRESULT {
  XSESSION_INFO info;
  xe::be<uint32_t> open_public_slots;
  xe::be<uint32_t> open_priv_slots;
  xe::be<uint32_t> filled_public_slots;
  xe::be<uint32_t> filled_priv_slots;
  xe::be<uint32_t> properties_count;
  xe::be<uint32_t> contexts_count;
  xe::be<uint32_t> properties_ptr;
  xe::be<uint32_t> contexts_ptr;
};

struct XSESSION_SEARCHRESULT_HEADER {
  xe::be<uint32_t> search_results_count;
  xe::be<uint32_t> search_results_ptr;
};

struct XSESSION_REGISTRATION_RESULTS {
  xe::be<uint32_t> registrants_count;
  xe::be<uint32_t> registrants_ptr;
};

struct XSESSION_REGISTRANT {
  xe::be<uint64_t> qwMachineID;
  xe::be<uint32_t> bTrustworthiness;
  xe::be<uint32_t> bNumUsers;
  xe::be<uint32_t> rgUsers;
};


X_HRESULT XgiApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                      uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x000B0018: {
      struct message_data {
        xe::be<uint32_t> hSession;
        xe::be<uint32_t> dwFlags;
        xe::be<uint32_t> dwMaxPublicSlots;
        xe::be<uint16_t> dwMaxPrivateSlots;
      }* data = reinterpret_cast<message_data*>(buffer);

      XELOGI(
          "XSessionModify({:08X} {:08X} {:08X} {:08X})",
          data->hSession, data->dwFlags, data->dwMaxPublicSlots, data->dwMaxPrivateSlots);

      return X_E_SUCCESS;
    }
    case 0x000B001C: {
      XELOGI("XSessionSearchEx");

      int i = 0;
      int j = 0;

      struct message_data {
        xe::be<uint32_t> proc_index;
        xe::be<uint32_t> user_index;
        xe::be<uint32_t> num_results;
        xe::be<uint16_t> num_props;
        xe::be<uint16_t> num_ctx;
        xe::be<uint32_t> props_ptr;
        xe::be<uint32_t> ctx_ptr;
        xe::be<uint32_t> cbResultsBuffer;
        xe::be<uint32_t> pSearchResults;
        xe::be<uint32_t> num_users;
      }* data = reinterpret_cast<message_data*>(buffer);

      auto* pSearchContexts =
          memory_->TranslateVirtual<XUSER_CONTEXT*>(data->ctx_ptr);

      uint32_t results_ptr = memory_->SystemHeapAlloc((uint32_t)data->cbResultsBuffer);
      auto* result = memory_->TranslateVirtual<XSESSION_SEARCHRESULT*>(results_ptr);

      auto resultsHeader =
          memory_->TranslateVirtual<XSESSION_SEARCHRESULT_HEADER*>(data->pSearchResults);

      // TODO: Remove hardcoded results, populate properly.

      resultsHeader->search_results_count = 9;
      resultsHeader->search_results_ptr = results_ptr;

      result[0].contexts_count = (uint32_t)data->num_ctx;
      result[0].properties_count = (uint32_t)data->num_props;
      result[0].contexts_ptr = data->ctx_ptr;
      result[0].properties_ptr = data->props_ptr;
      result[0].info.hostAddress.wPortOnline = 9103;
      result[0].info.hostAddress.ina.S_un.S_addr = 0x7F000001;
      result[0].filled_priv_slots = 0;
      result[0].filled_public_slots = 0;
      result[0].open_priv_slots = 2;
      result[0].open_public_slots = 2;

      return X_E_SUCCESS;
    }
    case 0x000B0021: {
      uint32_t pcbResults = xe::load_and_swap<uint32_t>(buffer + 20);
      uint32_t pResults = xe::load_and_swap<uint32_t>(buffer + 24);
      XELOGI("XamReadUserStats();");

      if (pResults) memset(memory_->TranslateVirtual(pResults), 0, pcbResults);
     
      return X_E_SUCCESS;
    }
    case 0x000B001A: {
      struct message_data {
        xe::be<uint32_t> session_handle;
        xe::be<uint32_t> flags;
        xe::be<uint32_t> unk1;
        xe::be<uint32_t> unk2;
        xe::be<uint32_t> session_nonce;
        xe::be<uint32_t> results_buffer_length;
        xe::be<uint32_t> results_buffer;
        xe::be<uint32_t> unk3;
      }* data = reinterpret_cast<message_data*>(buffer);
      XELOGI("XSessionArbitrationRegister({:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X}, {:08X});", 
          data->session_handle, data->flags, data->unk1, data->unk2,
          data->session_nonce, data->results_buffer_length,
          data->results_buffer, data->unk3);

      auto results =
          memory_->TranslateVirtual<XSESSION_REGISTRATION_RESULTS*>(
          data->results_buffer);

      // TODO: Remove hardcoded results, populate properly.

      results->registrants_count = 2;

      uint32_t registrants_ptr =
          memory_->SystemHeapAlloc(sizeof(XSESSION_REGISTRANT) * 2);
      auto* registrant =
          memory_->TranslateVirtual<XSESSION_REGISTRANT*>(registrants_ptr);

      results->registrants_ptr = registrants_ptr;

      registrant[0].bNumUsers = 1;
      registrant[0].qwMachineID = 1;
      registrant[0].bTrustworthiness = 1;

      uint32_t users_ptr = memory_->SystemHeapAlloc(sizeof(uint64_t) * 2);
      registrant[0].rgUsers = users_ptr;
      registrant[1].rgUsers = users_ptr + 8;

      auto* xuids = memory_->TranslateVirtual<uint64_t*>(users_ptr);

      xuids[0] = 0x000901FC3FB8FE71;
      xuids[1] = 0x000901FC3FB8FE72;

      return X_E_SUCCESS;
    }
    case 0x000B0006: {
      assert_true(!buffer_length || buffer_length == 24);
      // dword r3 user index
      // dword (unwritten?)
      // qword 0
      // dword r4 context enum
      // dword r5 value
      uint32_t user_index = xe::load_and_swap<uint32_t>(buffer + 0);
      uint32_t context_id = xe::load_and_swap<uint32_t>(buffer + 16);
      uint32_t context_value = xe::load_and_swap<uint32_t>(buffer + 20);
      XELOGD("XGIUserSetContextEx({:08X}, {:08X}, {:08X})", user_index,
             context_id, context_value);
      return X_E_SUCCESS;
    }
    case 0x000B0007: {
      uint32_t user_index = xe::load_and_swap<uint32_t>(buffer + 0);
      uint32_t property_id = xe::load_and_swap<uint32_t>(buffer + 16);
      uint32_t value_size = xe::load_and_swap<uint32_t>(buffer + 20);
      uint32_t value_ptr = xe::load_and_swap<uint32_t>(buffer + 24);
      XELOGD("XGIUserSetPropertyEx({:08X}, {:08X}, {}, {:08X})", user_index,
             property_id, value_size, value_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B0008: {
      assert_true(!buffer_length || buffer_length == 8);
      uint32_t achievement_count = xe::load_and_swap<uint32_t>(buffer + 0);
      uint32_t achievements_ptr = xe::load_and_swap<uint32_t>(buffer + 4);
      XELOGD("XGIUserWriteAchievements({:08X}, {:08X})", achievement_count,
             achievements_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B0010: {
      assert_true(!buffer_length || buffer_length == 28);
      // Sequence:
      // - XamSessionCreateHandle
      // - XamSessionRefObjByHandle
      // - [this]
      // - CloseHandle
      uint32_t session_ptr = xe::load_and_swap<uint32_t>(buffer + 0x0);
      uint32_t flags = xe::load_and_swap<uint32_t>(buffer + 0x4);
      uint32_t num_slots_public = xe::load_and_swap<uint32_t>(buffer + 0x8);
      uint32_t num_slots_private = xe::load_and_swap<uint32_t>(buffer + 0xC);
      uint32_t user_xuid = xe::load_and_swap<uint32_t>(buffer + 0x10);
      uint32_t session_info_ptr = xe::load_and_swap<uint32_t>(buffer + 0x14);
      uint32_t nonce_ptr = xe::load_and_swap<uint32_t>(buffer + 0x18);

      XELOGD(
          "XGISessionCreateImpl({:08X}, {:08X}, {}, {}, {:08X}, {:08X}, "
          "{:08X})",
          session_ptr, flags, num_slots_public, num_slots_private, user_xuid,
          session_info_ptr, nonce_ptr);
      return X_E_SUCCESS;
    }
    case 0x000B0011: {
      // TODO(PermaNull): reverse buffer contents.
      XELOGD("XGISessionDelete");
      return X_STATUS_SUCCESS;
    }
    case 0x000B0012: {
      assert_true(buffer_length == 0x14);
      uint32_t session_ptr = xe::load_and_swap<uint32_t>(buffer + 0x0);
      uint32_t user_count = xe::load_and_swap<uint32_t>(buffer + 0x4);
      uint32_t unk_0 = xe::load_and_swap<uint32_t>(buffer + 0x8);
      uint32_t user_index_array = xe::load_and_swap<uint32_t>(buffer + 0xC);
      uint32_t private_slots_array = xe::load_and_swap<uint32_t>(buffer + 0x10);

      assert_zero(unk_0);
      XELOGD("XGISessionJoinLocal({:08X}, {}, {}, {:08X}, {:08X})", session_ptr,
             user_count, unk_0, user_index_array, private_slots_array);
      return X_E_SUCCESS;
    }
    case 0x000B0014: {
      // Gets 584107FB in game.
      // get high score table?
      XELOGD("XGI_unknown");
      return X_STATUS_SUCCESS;
    }
    case 0x000B0015: {
      // send high scores?
      XELOGD("XGI_unknown");
      return X_STATUS_SUCCESS;
    }
    case 0x000B0041: {
      assert_true(!buffer_length || buffer_length == 32);
      // 00000000 2789fecc 00000000 00000000 200491e0 00000000 200491f0 20049340
      uint32_t user_index = xe::load_and_swap<uint32_t>(buffer + 0);
      uint32_t context_ptr = xe::load_and_swap<uint32_t>(buffer + 16);
      auto context =
          context_ptr ? memory_->TranslateVirtual(context_ptr) : nullptr;
      uint32_t context_id =
          context ? xe::load_and_swap<uint32_t>(context + 0) : 0;
      XELOGD("XGIUserGetContext({:08X}, {:08X}{:08X}))", user_index,
             context_ptr, context_id);
      uint32_t value = 0;
      if (context) {
        xe::store_and_swap<uint32_t>(context + 4, value);
      }
      return X_E_FAIL;
    }
    case 0x000B0071: {
      XELOGD("XGI 0x000B0071, unimplemented");
      return X_E_SUCCESS;
    }
  }
  XELOGE(
      "Unimplemented XGI message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace xe
