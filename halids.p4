/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define CLASS_NOT_SET 10000// A big number
#define MAX_REGISTER_ENTRIES 8192

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
  bit<64> feature3;
  bit<64> feature5;

  bit<16> prevFeature;
  bit<16> isTrue;

  bit<16> class;
  bit<16> node_id;

  bit<1> direction;
  bit<32> register_index;
  bit<32> register_index_inverse;

  bit<32> srcip;
  bit<16> srcport;
  bit<16> dstport;
  bit<16> hdr_srcport;
  bit<16> hdr_dstport;
  bit<8> sttl;
  bit<8> dttl;

  bit<32> dpkts;

  bit<1> is_first;
  bit<1> is_hash_collision;
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
  register<bit<8>>(MAX_REGISTER_ENTRIES) reg_ttl;
  register<bit<8>>(MAX_REGISTER_ENTRIES) reg_dttl;

  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dpkts;

  //Registers for identifying the flow more apart from hash we may use source port
  register<bit<32>>(max_register_entries) reg_srcip;
  register<bit<16>>(max_register_entries) reg_srcport;
  register<bit<16>>(max_register_entries) reg_dstport;

  action init_register() {
    //intialise the registers to 0
    reg_srcip.write(meta.register_index, 0);
    reg_srcport.write(meta.register_index, 0);
    reg_dstport.write(meta.register_index, 0);
    reg_ttl.write(meta.register_index, 0);
    reg_dttl.write(meta.register_index, 0);
    reg_dpkts.write(meta.register_index, 0);
  }

  action get_register_index_tcp() {
    //Get register position
    hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        hdr.tcp.srcPort,
        hdr.tcp.dstPort,
        hdr.ipv4.protocol},
        (bit<32>)MAX_REGISTER_ENTRIES);
  }

  action get_register_index_udp() {
    hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        hdr.udp.srcPort,
        hdr.udp.dstPort,
        hdr.ipv4.protocol},
        (bit<32>)MAX_REGISTER_ENTRIES);
  }

  action get_register_index_inverse_tcp() {
    //Get register position for the same flow in another directon
    // just inverse the src and dst
    hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
        hdr.ipv4.srcAddr,
        hdr.tcp.dstPort,
        hdr.tcp.srcPort,
        hdr.ipv4.protocol},
        (bit<32>)MAX_REGISTER_ENTRIES);
  }

  action get_register_index_inverse_udp() {
    hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
        hdr.ipv4.srcAddr,
        hdr.udp.dstPort,
        hdr.udp.srcPort,
        hdr.ipv4.protocol},
        (bit<32>)MAX_REGISTER_ENTRIES);
  }

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
    meta.feature1 = (bit<64>)meta.sttl;
    meta.feature3 = (bit<64>)meta.dttl;
    meta.feature5 = (bit<64>)meta.dpkts;
  }

  action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<64> threshold) {
    bit<64> feature = 0;
    bit<64> th = threshold;
    bit<16> f = f_inout + 1;

    if (f==1){
      feature = meta.feature1;
    }
    else if (f==3){
      feature = meta.feature3;
    }
    else if (f==5){
      feature = meta.feature5;
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

  action SetDirection() {
    //need just for this setting as tcpreplay is sending all the packets to same interface
    meta.direction = 1;
  }

  table direction{
    key = {
      hdr.ipv4.dstAddr: lpm;
    }
    actions = {
      NoAction;
      SetDirection;
    }
    size = 10;
    default_action = NoAction();
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
    direction.apply();
    meta.class = CLASS_NOT_SET;

    //TODO: if (hdr.packet_out.isValid()) meant for packets from controller

    if (hdr.ipv4.isValid()) {
      if (hdr.ipv4.protocol == 1 || hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17) {//We treat only TCP or UDP packets (and ICMP for testing)
        if (meta.direction == 1) {
          if (hdr.ipv4.protocol == 6) {
            get_register_index_tcp();
            meta.hdr_srcport = hdr.tcp.srcPort;
            meta.hdr_dstport = hdr.tcp.dstPort;
          }
          else {
            get_register_index_udp();
            meta.hdr_srcport = hdr.udp.srcPort;
            meta.hdr_dstport = hdr.udp.dstPort;
          }

          //read_reg_to_check_collision srcip, srcport, dstport
          reg_srcip.read(meta.srcip, meta.register_index);
          reg_srcport.read(meta.srcport, meta.register_index);
          reg_dstport.read(meta.dstport, meta.register_index);

          if (meta.srcip == 0) {//It was an empty register
            meta.is_first = 1;
          }
          else if (meta.srcip != hdr.ipv4.srcAddr || meta.srcport != meta.hdr_srcport
              || meta.dstport != meta.hdr_dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.srcAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);
            }

            meta.sttl = hdr.ipv4.ttl;
            reg_ttl.write((bit<32>)meta.register_index, meta.sttl);

            reg_dttl.read(meta.dttl, (bit<32>)meta.register_index);

            // tcprtt
            //SYN TIME
            //TODO: if-else calculo tcprtt

            //read all reverse flow features
            reg_dpkts.read(meta.dpkts, (bit<32>)meta.register_index);
          }//hash collision check
        }//end of direction = 1

        else {//direction = 0
          if (hdr.ipv4.protocol == 6) {
            get_register_index_inverse_tcp();
            meta.hdr_srcport = hdr.tcp.dstPort;//its inverse
            meta.hdr_dstport = hdr.tcp.srcPort;
          }
          else {
            get_register_index_inverse_udp();
            meta.hdr_srcport = hdr.udp.dstPort;
            meta.hdr_dstport = hdr.udp.srcPort;
          }

          meta.register_index = meta.register_index_inverse;

          //read_reg_to_check_collision srcip, srcport, dstport
          reg_srcip.read(meta.srcip, meta.register_index);
          reg_srcport.read(meta.srcport, meta.register_index);
          reg_dstport.read(meta.dstport, meta.register_index);
          if (meta.srcip == 0) {//It was an empty register
            meta.is_first = 1;
          }
          else if (meta.srcip != hdr.ipv4.dstAddr || meta.srcport != meta.hdr_srcport
              || meta.dstport != meta.hdr_dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {//shouldn't happen!
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.dstAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);

            }

            reg_dpkts.read(meta.dpkts, (bit<32>)meta.register_index);
            meta.dpkts = meta.dpkts + 1;
            reg_dpkts.write((bit<32>)meta.register_index, meta.dpkts);

            meta.dttl =  hdr.ipv4.ttl;
            reg_dttl.write((bit<32>)meta.register_index, meta.dttl);
            reg_ttl.read(meta.sttl, (bit<32>)meta.register_index);
          }//hash collision check
        }

        if (meta.is_hash_collision == 0) {
          init_features();

          //start with parent node of decision tree
          meta.node_id = 0;
          meta.prevFeature = 0;
          meta.isTrue = 1;

          //TODO if malware

          level1.apply();
          if (meta.class == CLASS_NOT_SET) {
            level2.apply();
          } // level2
        }//hash collision check
      }

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
