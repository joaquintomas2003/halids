/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define CLASS_NOT_SET 10000// A big number

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

typedef bit<16> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
  macAddr_t dstAddr;
  macAddr_t srcAddr;
  bit<16>   etherType;
}

header ipv4_t {
  bit<4>    version;
  bit<4>    ihl;
  bit<8>    diffserv;
  bit<16>   totalLen;
  bit<16>   identification;
  bit<3>    flags;
  bit<13>   fragOffset;
  bit<8>    ttl;
  bit<8>    protocol;
  bit<16>   hdrChecksum;
  ip4Addr_t srcAddr;
  ip4Addr_t dstAddr;
}


header tcp_t{
  bit<16> srcPort;
  bit<16> dstPort;
  bit<32> seqNo;
  bit<32> ackNo;
  bit<4>  dataOffset;
  bit<4>  res;
  bit<1>  cwr;
  bit<1>  ece;
  bit<1>  urg;
  bit<1>  ack;
  bit<1>  psh;
  bit<1>  rst;
  bit<1>  syn;
  bit<1>  fin;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
}

header udp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<16> length_;
  bit<16> checksum;
}

struct metadata {
  bit<64> feature1;
  bit<64> feature2;
  bit<16> prevFeature;
  bit<16> isTrue;
  bit<16> class;
  bit<16> node_id;
}

struct headers {
  ethernet_t   ethernet;
  ipv4_t       ipv4;
  tcp_t        tcp;
  udp_t        udp;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {

  state start {
    transition parse_ethernet;
  }

  state parse_ethernet {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
      TYPE_IPV4: parse_ipv4;
      default: accept;
    }
  }

  state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
      6: parse_tcp;
      17: parse_udp;
      default: accept;
    }
  }

  state parse_tcp {
    packet.extract(hdr.tcp);
    transition accept;
  }

  state parse_udp {
    packet.extract(hdr.udp);
    transition accept;
  }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
  apply {  }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
  action drop() {
    mark_to_drop();
  }

  action ipv4_forward(egressSpec_t port) {
    standard_metadata.egress_spec = port;
    //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //hdr.ethernet.dstAddr = dstAddr;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
  }

  action init_features(){
    meta.feature1 = (bit<64>)hdr.ipv4.protocol;
    meta.feature2 = (bit<64>)hdr.ipv4.ttl;
  }

  action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<64> threshold) {
    bit<64> feature = 0;
    bit<64> th = threshold;
    bit<16> f = f_inout + 1;

    if (f==1){
      feature = meta.feature1;
    }
    else if (f==2){
      feature = meta.feature2;
    }

    if(feature <= th) meta.isTrue = 1;
    else meta.isTrue = 0;

    meta.prevFeature = f_inout;
    meta.node_id = node_id;
  }

  action SetClass(bit<16> node_id, bit<16> class) {
    meta.class = class;
    meta.node_id = node_id;
  }

  table level1{
    key = {
      meta.node_id: exact;
      meta.prevFeature: exact;
      meta.isTrue: exact;
    }
    actions = {
      NoAction;
      CheckFeature;
      SetClass;
    }
    size = 1024;
  }

  table level2{
    key = {
      meta.node_id: exact;
      meta.prevFeature: exact;
      meta.isTrue: exact;
    }
    actions = {
      NoAction;
      CheckFeature;
      SetClass;
    }
    size = 1024;
  }

  table level3{
    key = {
      meta.node_id: exact;
      meta.prevFeature: exact;
      meta.isTrue: exact;
    }
    actions = {
      NoAction;
      CheckFeature;
      SetClass;
    }
    size = 1024;
  }

  /* This will send the packet to a specifique port of the switch for output*/
  table ipv4_exact {
    key = {
      meta.class: exact;
    }
    actions = {
      ipv4_forward;
      drop;
      NoAction;
    }
    size = 1024;
    default_action = drop();
  }

  apply {
    meta.class = CLASS_NOT_SET;

    if (hdr.ipv4.isValid()) {
      init_features();

      // start with parent node of decision tree
      meta.node_id = 0;
      meta.prevFeature = 0;
      meta.isTrue = 1;

      level1.apply();
      if (meta.class == CLASS_NOT_SET) {
        level2.apply();
        if (meta.class == CLASS_NOT_SET) {
          level3.apply();
        } // level2
      } // level3

      ipv4_exact.apply();
    }
  }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
  apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
  apply {
    update_checksum(
      hdr.ipv4.isValid(),
      { hdr.ipv4.version,
      hdr.ipv4.ihl,
      hdr.ipv4.diffserv,
      hdr.ipv4.totalLen,
      hdr.ipv4.identification,
      hdr.ipv4.flags,
      hdr.ipv4.fragOffset,
      hdr.ipv4.ttl,
      hdr.ipv4.protocol,
      hdr.ipv4.srcAddr,
      hdr.ipv4.dstAddr },
      hdr.ipv4.hdrChecksum,
      HashAlgorithm.csum16
    );
  }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.tcp);
    packet.emit(hdr.udp);
  }
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;
