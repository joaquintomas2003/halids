/* Copyright (C) 2017,  Netronome Systems, Inc.  All rights reserved. */

#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include <mac_time.h>
#include "pif_plugin.h"

int pif_plugin_populate_if_ts(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {
  PIF_PLUGIN_ethernet_T *ethernet;

  __xread struct mac_time_state mac_time_xfer;

  mac_time_fetch(&mac_time_xfer);

  ethernet = pif_plugin_hdr_get_ethernet(headers);

  ethernet->dstAddr = mac_time_xfer.mac_time_s;

  return PIF_PLUGIN_RETURN_FORWARD;
}
