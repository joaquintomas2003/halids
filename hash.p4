/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define MAX_REGISTER_ENTRIES 131072

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
  bit<6>    dSField;
  bit<2>    ecn;
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
  bit<1>  direction;
  bit<1>  is_first;
  bit<1>  is_hash_collision;
  bit<32> register_index;
  bit<32> register_index_inverse;
  bit<32> srcip;
  bit<16> srcport;
  bit<16> dstport;
  bit<32> hdr_srcip;
  bit<16> hdr_srcport;
  bit<16> hdr_dstport;
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
  register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dstport;
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_srcip;
  register<bit<16>>(MAX_REGISTER_ENTRIES) reg_srcport;
  register<bit<48>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;

  counter(16, CounterType.packets) counter_;

  action init_register() {
    reg_dstport.write(meta.register_index, 0);
    reg_srcip.write(meta.register_index, 0);
    reg_srcport.write(meta.register_index, 0);
  }

  action get_register_index_tcp() {
    //Get register position
    hash(
      meta.register_index,
      HashAlgorithm.crc32,
      (bit<16>)0,
      {
        hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        hdr.tcp.srcPort,
        hdr.tcp.dstPort,
        hdr.ipv4.protocol
      },
      (bit<32>)MAX_REGISTER_ENTRIES);
  }

  action get_register_index_udp() {
    hash(
      meta.register_index,
      HashAlgorithm.crc32,
      (bit<16>)0,
      {
        hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr,
        hdr.udp.srcPort,
        hdr.udp.dstPort,
        hdr.ipv4.protocol
      },
      (bit<32>)MAX_REGISTER_ENTRIES);
  }

  action get_register_index_inverse_tcp() {
    //Get register position for the same flow in another directon
    // just inverse the src and dst
    hash(
      meta.register_index_inverse,
      HashAlgorithm.crc32,
      (bit<16>)0,
      {
        hdr.ipv4.dstAddr,
        hdr.ipv4.srcAddr,
        hdr.tcp.dstPort,
        hdr.tcp.srcPort,
        hdr.ipv4.protocol
      },
      (bit<32>)MAX_REGISTER_ENTRIES);
  }

  action get_register_index_inverse_udp() {
    hash(
      meta.register_index_inverse,
      HashAlgorithm.crc32,
      (bit<16>)0,
      {
        hdr.ipv4.dstAddr,
        hdr.ipv4.srcAddr,
        hdr.udp.dstPort,
        hdr.udp.srcPort,
        hdr.ipv4.protocol
      },
      (bit<32>)MAX_REGISTER_ENTRIES);
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

  apply {
    direction.apply();

    counter_.count(0); // Packet count

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
          else if (meta.srcip != hdr.ipv4.srcAddr || meta.hdr_srcport != meta.srcport
              || meta.hdr_dstport != meta.dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
            counter_.count(1); // Hash collision count
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.srcAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);
            }
          }
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
          else if (meta.srcip != hdr.ipv4.dstAddr || meta.hdr_srcport != meta.srcport
              || meta.hdr_dstport != meta.dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
            counter_.count(1); // Hash collision count
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {//shouldn't happen!
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.dstAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);
            }
          }//hash collision check
        }
      }
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
      hdr.ipv4.dSField,
      hdr.ipv4.ecn,
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
