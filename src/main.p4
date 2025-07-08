/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define CLASS_NOT_SET 10000// A big number
#define MAX_REGISTER_ENTRIES 32768

#define STATE_INT 1
#define STATE_FIN 2
#define STATE_REQ 3
#define STATE_CON 4
#define STATE_ACC 5
#define STATE_CLO 6
#define STATE_EST 7

#define THRESHOLD_CERTAINTY 100
#define SEND_TO_ORACLE 2

#define CPU_PORT 768

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

typedef bit<16> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

struct intrinsic_metadata_t {
  bit<64> ingress_global_timestamp;
}

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

// packetIn is the packet sent from switch to controller. (from controller view)
// packetOut is the packet sent from controller to switch. (from controller view)
const bit<8> PACKET_TYPE_IN  = 1;
const bit<8> PACKET_TYPE_OUT = 2;

const bit<8> OPCODE_NO_OP         = 0;
const bit<8> OPCODE_SEND_FEATURES = 1;
const bit<8> OPCODE_RCV_LABEL     = 2;

// packet from the controller (label)
header packet_out_header_t {
  bit<8>                  packet_type; // 1 byte
  bit<8>                  opcode; // 1 byte
  bit<32>                 flow_hash; // 4 bytes
  bit<16>                 label; // 2 bytes
  bit<1>                  malware;
  bit<1>                  is_first;
  bit<6>                  reserved;
} // 9 bytes

// packet to the controller (send features)
header packet_in_header_t {
  bit<8>                  packet_type; // 1 byte
  bit<8>                  opcode; // 1 byte
  bit<32>                 flow_hash; // 4 byte
  bit<64>                 feature1; // 8 bytes
  bit<64>                 feature2; // 8 bytes
  bit<64>                 feature3; // 8 bytes
  bit<64>                 feature4; // 8 bytes
  bit<64>                 feature5; // 8 bytes
  bit<64>                 feature6; // 8 bytes
  bit<64>                 feature7; // 8 bytes
  bit<64>                 feature8; // 8 bytes
  bit<64>                 feature9; // 8 bytes
  bit<64>                 feature10; // 8 bytes
  bit<64>                 feature11; // 8 bytes
  bit<64>                 feature12; // 8 bytes
  bit<64>                 dur; // 8 bytes
  bit<64>                 sbytes; // 8 bytes
  bit<64>                 dpkts; // 8 bytes
  bit<64>                 spkts; // 8 bytes
  bit<1>                  malware;
  bit<1>                  is_first;
  bit<6>                  reserved;
} // 135 bytes

struct metadata {
  bit<16> class;
  bit<8>  ct_state_ttl;
  bit<32> dbytes;
  bit<1>  direction;
  bit<32> dpkts;
  bit<16> dstport;
  bit<8>  dttl;
  bit<32> dur;
  bit<32> feature1;
  bit<32> feature2;
  bit<32> feature3;
  bit<32> feature4;
  bit<32> feature5;
  bit<32> feature6;
  bit<32> feature7;
  bit<32> feature8;
  bit<32> feature9;
  bit<32> feature10;
  bit<32> feature11;
  bit<32> feature12;
  bit<1>  first_ack;
  bit<16> hdr_dstport;
  bit<16> hdr_srcport;
  bit<32> hdr_srcip;
  bit<16> isTrue;
  bit<1>  is_first;
  bit<1>  is_hash_collision;
  bit<16> node_id;
  bit<16> prevFeature;
  bit<32> register_index;
  bit<32> register_index_inverse;
  bit<32> sbytes;
  bit<32> spkts;
  bit<32> srcip;
  bit<16> srcport;
  bit<8>  state;
  bit<8>  sttl;
  bit<64> syn_time;
  bit<64> tcprtt;
  bit<64> time_first_pkt;
  bit<1> malware;
  bit<1> marked_malware;
  intrinsic_metadata_t intrinsic_metadata;
}

struct headers {
  ethernet_t   ethernet;
  ipv4_t       ipv4;
  tcp_t        tcp;
  udp_t        udp;
  packet_in_header_t packet_in_hdr;
  packet_out_header_t packet_out_hdr;
}

/*************************************************************************
 *********************** P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {

  state start {
    transition parse_sender;
  }

  state parse_sender {
    transition select(standard_metadata.ingress_port) {
      CPU_PORT: parse_packet_oracle; // packet received from the oracle with prediction
      default: parse_ethernet;
    }
  }

  state parse_packet_oracle {
    // extract hdr that contains predicted label by oracle
    packet.extract(hdr.packet_out_hdr);
    transition accept;
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
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dbytes;
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dpkts;
  register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dstport;
  register<bit<8>>(MAX_REGISTER_ENTRIES)  reg_dttl;
  register<bit<1>>(MAX_REGISTER_ENTRIES)  reg_first_ack;
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_sbytes;
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_spkts;
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_srcip;
  register<bit<16>>(MAX_REGISTER_ENTRIES) reg_srcport;
  register<bit<64>>(MAX_REGISTER_ENTRIES) reg_syn_time;
  register<bit<64>>(MAX_REGISTER_ENTRIES) reg_tcprtt;
  register<bit<64>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;
  register<bit<8>>(MAX_REGISTER_ENTRIES)  reg_ttl;
  register<bit<1>>(MAX_REGISTER_ENTRIES) reg_marked_malware;


  counter(7, CounterType.packets) counter_;

  action init_register() {
    reg_dbytes.write(meta.register_index, 0);
    reg_dpkts.write(meta.register_index, 0);
    reg_dstport.write(meta.register_index, 0);
    reg_dttl.write(meta.register_index, 0);
    reg_sbytes.write(meta.register_index, 0);
    reg_spkts.write(meta.register_index, 0);
    reg_srcip.write(meta.register_index, 0);
    reg_srcport.write(meta.register_index, 0);
    reg_syn_time.write(meta.register_index, 0);
    reg_tcprtt.write(meta.register_index, 0);
    reg_ttl.write(meta.register_index, 0);
    reg_marked_malware.write(meta.register_index, 0);
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

  action calc_state() {
    //When Sload or Dload is 0 the state can be INT
    //Thus need to calculate sload, dload before
    // XX TODO Argus log shows only last state!
    //XX TODO The following logic is only approx. correct!
    if ((meta.is_first == 1)||(meta.dttl == 0)) {
      if (hdr.ipv4.protocol == 6) //TCP
        meta.state = STATE_REQ;
      else meta.state = STATE_INT;
    }
    else {
      if (hdr.ipv4.protocol == 6) //TCP
        meta.state = STATE_EST;
      else meta.state = STATE_CON;
    }
    //TODO for STATE_FIN, which may not be useful as it would be last packet of transaction
    if (hdr.ipv4.protocol == 6 && hdr.tcp.fin == (bit<1>)1) {
      meta.state = STATE_FIN;
    }
  }

  action calc_ct_state_ttl(){
    meta.ct_state_ttl = 0;
    if ((meta.sttl == 62 || meta.sttl == 63 || meta.sttl == 254 || meta.sttl == 255)
        && (meta.dttl == 252 || meta.dttl == 253) && meta.state == STATE_FIN) {
      meta.ct_state_ttl = 1;
    }
    else if ((meta.sttl == 0 || meta.sttl == 62 || meta.sttl == 254)
        && (meta.dttl == 0) && meta.state == STATE_INT) {
      meta.ct_state_ttl = 2;
    }
    else if((meta.sttl == 62 || meta.sttl == 254)
        && (meta.dttl == 60 || meta.dttl == 252 || meta.dttl == 253)
        && meta.state == STATE_CON){
      meta.ct_state_ttl = 3;
    }
    else if((meta.sttl == 254) && (meta.dttl == 252) && meta.state == STATE_ACC){
      meta.ct_state_ttl = 4;
    }
    else if((meta.sttl == 254) && (meta.dttl == 252) && meta.state == STATE_CLO){
      meta.ct_state_ttl = 5;
    }
    else if((meta.sttl == 254) && (meta.dttl == 0) && meta.state == STATE_REQ){
      meta.ct_state_ttl = 7;
    }
    else {
      meta.ct_state_ttl = 0;
    }
  }
  action init_features(){
    meta.feature1 = (bit<32>)meta.sttl;
    meta.feature2 = (bit<32>)meta.ct_state_ttl;
    meta.feature3 = (bit<32>)meta.dttl;
    meta.feature4 = meta.sbytes * (meta.spkts - 1) * 8;
    meta.feature5 = meta.dpkts;
    meta.feature6 = meta.dbytes;
    meta.feature7 = meta.sbytes;
    meta.feature8 = meta.dbytes * (meta.dpkts - 1) * 8;
    meta.feature9 = meta.sbytes;
    meta.feature10 = (bit<32>)meta.tcprtt;
    meta.feature11 = (bit<32>)meta.dstport;
    meta.feature12 = meta.dur;
  }

  action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<32> threshold) {
    bit<32> feature = 0;
    bit<32> th = threshold;
    bit<16> f = f_inout + 1;
    counter_.count(1);

    if (f==1){
      feature = meta.feature1;
    }
    else if (f == 2) {
      feature = meta.feature2;
    }
    else if (f==3){
      feature = meta.feature3;
    }
    else if (f==4){
      feature = meta.feature4 * 1000000;
      bit<32> th_aux = th * meta.dur;
      th = th_aux * meta.sbytes;
    }
    else if (f==5){
      feature = meta.feature5;
    }
    else if (f==6){
      feature = meta.feature6;
      th = th * meta.dpkts;
    }
    else if (f==7){
      feature = meta.feature7;
      th = th * meta.dpkts;
    }
    else if (f==8){
      feature = meta.feature8 * 1000000;
      bit<32> th_aux = th * meta.dur;
      th = th_aux * meta.sbytes;
    }
    else if (f==9){
      feature = meta.feature9;
      th = th * meta.spkts;
    }
    else if (f==10){
      feature = meta.feature10;
    }
    else if (f==11){
      feature = meta.feature11;
    }
    else if (f==12){
      feature = meta.feature12;
    }

    if(feature <= th) meta.isTrue = 1;
    else meta.isTrue = 0;

    meta.prevFeature = f_inout;
    meta.node_id = node_id;
  }

  action send_to_oracle() {
    // header to send packet to controller
    hdr.packet_in_hdr.setValid();

    // set egress port to CPU PORT
    standard_metadata.egress_spec = CPU_PORT;
    hdr.packet_in_hdr.packet_type = PACKET_TYPE_IN; // metadata id 1
    hdr.packet_in_hdr.opcode = OPCODE_SEND_FEATURES; // id 2

    // features to send to the controller
    hdr.packet_in_hdr.flow_hash = meta.register_index; // id 3
    hdr.packet_in_hdr.feature1 = (bit<64>)meta.feature1; // id 4
    hdr.packet_in_hdr.feature2 = (bit<64>)meta.feature2;
    hdr.packet_in_hdr.feature3 = (bit<64>)meta.feature3;
    hdr.packet_in_hdr.feature4 = (bit<64>)meta.feature4;
    hdr.packet_in_hdr.feature5 = (bit<64>)meta.feature5;
    hdr.packet_in_hdr.feature6 = (bit<64>)meta.feature6;
    hdr.packet_in_hdr.feature7 = (bit<64>)meta.feature7;
    hdr.packet_in_hdr.feature8 = (bit<64>)meta.feature8;
    hdr.packet_in_hdr.feature9 = (bit<64>)meta.feature9;
    hdr.packet_in_hdr.feature10 = (bit<64>)meta.feature10;
    hdr.packet_in_hdr.feature11 = (bit<64>)meta.feature11;
    hdr.packet_in_hdr.feature12 = (bit<64>)meta.feature12;  // id 15

    // needed to calculate some features at the oracle (in the data plane the treshold is changed)
    hdr.packet_in_hdr.dur = (bit<64>)meta.dur;  // id 16
    hdr.packet_in_hdr.sbytes = (bit<64>)meta.sbytes; // id 17
    hdr.packet_in_hdr.dpkts = (bit<64>)meta.dpkts;  // id 18
    hdr.packet_in_hdr.spkts = (bit<64>)meta.spkts;  // id 19
    hdr.packet_in_hdr.malware = meta.malware; // send priori knowledge of malware
    hdr.packet_in_hdr.is_first = meta.is_first;
    hdr.packet_in_hdr.reserved = 0;
  }

  action SetClass(bit<16> node_id, bit<16> class, bit<8> certainty) {
    meta.node_id = node_id;
    counter_.count(2);

    if (certainty > THRESHOLD_CERTAINTY) {
      meta.class = class;
    }
    else {
      meta.class = SEND_TO_ORACLE;
    }
  }

  action SetDirection() {
    //need just for this setting as tcpreplay is sending all the packets to same interface
    meta.direction = 1;
  }

  action SetMalware() {
    //need just for this setting as tcpreplay is sending all the packets to same interface
    meta.malware = 1;
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
  table level4{
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

  table level5{
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

  apply {
    const bit<16> MAX_LEN = 1500;

    if (standard_metadata.packet_length > 1000 ) {
      counter_.count(6);
      mark_to_drop();
    }

    meta.direction = 0;

    direction.apply();

    meta.class = CLASS_NOT_SET;

    if (hdr.ipv4.isValid()) {
      if (hdr.ipv4.protocol == 1 || hdr.ipv4.protocol == 6) {//We treat only TCP or UDP packets (and ICMP for testing)
        counter_.count(0);
        meta.is_hash_collision = 0;

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
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {
              meta.time_first_pkt = meta.intrinsic_metadata.ingress_global_timestamp;
              reg_time_first_pkt.write((bit<32>)meta.register_index, meta.time_first_pkt);
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.srcAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);
            }

            reg_spkts.read(meta.spkts, (bit<32>)meta.register_index);
            meta.spkts = meta.spkts + 1;
            reg_spkts.write((bit<32>)meta.register_index, meta.spkts);

            meta.sttl = hdr.ipv4.ttl;
            reg_ttl.write((bit<32>)meta.register_index, meta.sttl);

            reg_dttl.read(meta.dttl, (bit<32>)meta.register_index);

            //read_sbytes also used for sload
            reg_sbytes.read(meta.sbytes, (bit<32>)meta.register_index);
            meta.sbytes = meta.sbytes + (bit<32>)standard_metadata.packet_length - 14;
            reg_sbytes.write((bit<32>)meta.register_index, meta.sbytes);

            // tcprtt
            //SYN TIME
            if ((hdr.tcp.ack != (bit<1>)1)&&(hdr.tcp.syn == (bit<1>)1)) {//this is a SYN
              reg_syn_time.write((bit<32>)meta.register_index, meta.intrinsic_metadata.ingress_global_timestamp);
            }
            //ACK + SYN time
            else if ((hdr.tcp.ack == (bit<1>)1)&&(hdr.tcp.syn != (bit<1>)1)) {//this is an ACK
              reg_first_ack.read(meta.first_ack, (bit<32>)meta.register_index);

              if (meta.first_ack == 0) {
                //sum of synack(SYN to SYN_ACK time) and ackdat(SYN_ACK to ACK time)
                reg_syn_time.read(meta.syn_time, (bit<32>)meta.register_index);

                if (meta.syn_time > 0) {//There was a syn before
                  meta.tcprtt = meta.intrinsic_metadata.ingress_global_timestamp - meta.syn_time;
                  reg_tcprtt.write((bit<32>)meta.register_index, meta.tcprtt);
                  //no longer a first ack
                  reg_first_ack.write((bit<32>)meta.register_index, 1);
                }
              }
            }

            //read all reverse flow features
            reg_dbytes.read(meta.dbytes, (bit<32>)meta.register_index);
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
          else if (meta.srcip != hdr.ipv4.dstAddr || meta.hdr_srcport != meta.srcport
              || meta.hdr_dstport != meta.dstport) {
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

            reg_dbytes.read(meta.dbytes, (bit<32>)meta.register_index);
            meta.dbytes = meta.dbytes + (bit<32>)standard_metadata.packet_length - 14;
            reg_dbytes.write((bit<32>)meta.register_index, meta.dbytes);

            meta.dttl =  hdr.ipv4.ttl;
            reg_dttl.write((bit<32>)meta.register_index, meta.dttl);
            reg_ttl.read(meta.sttl, (bit<32>)meta.register_index);
            reg_sbytes.read(meta.sbytes, (bit<32>)meta.register_index);
            reg_spkts.read(meta.spkts, (bit<32>)meta.register_index);
          }//hash collision check
        }

        if (meta.is_hash_collision == 0) {
          reg_time_first_pkt.read(meta.time_first_pkt, (bit<32>)meta.register_index);
          meta.dur = (bit<32>)(meta.intrinsic_metadata.ingress_global_timestamp - meta.time_first_pkt);

          calc_state();
          calc_ct_state_ttl();

          init_features();

          //start with parent node of decision tree
          meta.node_id = 0;
          meta.prevFeature = 0;
          meta.isTrue = 1;

          reg_marked_malware.read(meta.marked_malware, (bit<32>)meta.register_index);

          if (meta.marked_malware == 1) {
            meta.class = 1; //No need to check again!
          }
          else{
            level1.apply();
            if (meta.class == CLASS_NOT_SET) {
              level2.apply();
              if (meta.class == CLASS_NOT_SET) {
                level3.apply();
              }
            }
          }
        }//hash collision check

        if (meta.class == SEND_TO_ORACLE || meta.class == CLASS_NOT_SET) {
          send_to_oracle();
          counter_.count(3); // Send to oracle count
        }else if(meta.class == 0) {
          standard_metadata.egress_spec = 771;
          counter_.count(4);
        } else if (meta.class == 1){
          standard_metadata.egress_spec = 770;
          counter_.count(5);
        };
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
    packet.emit(hdr.packet_out_hdr);
    packet.emit(hdr.packet_in_hdr);
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
