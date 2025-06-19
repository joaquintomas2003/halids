/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define CLASS_NOT_SET 10000// A big number
#define MAX_REGISTER_ENTRIES 8192

#define STATE_INT 1
#define STATE_FIN 2
#define STATE_REQ 3
#define STATE_CON 4
#define STATE_ACC 5
#define STATE_CLO 6
#define STATE_EST 7

#define THRESHOLD_CERTAINTY 80
#define SEND_TO_ORACLE 2

#define CPU_PORT 768

/*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

typedef bit<16> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

extern void set_ingress_timestamp();

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

header features_t {
    bit<64> feature1;
    bit<64> feature2;
    bit<64> feature3;
    bit<64> feature4;
    bit<64> feature5;
    bit<64> feature6;
    bit<64> feature7;
    bit<64> feature8;
    bit<64> feature9;
    bit<64> feature10;
    bit<64> feature11;
    bit<64> feature12;
    bit<64> dur;
    bit<64> sbytes;
    bit<64> dpkts;
    bit<64> spkts;
    bit<1>  malware;
    bit<1>  is_first;
    bit<62> padding;  // xa hacerlo múltiplo de 8 bytes (64 bits)
} // 136 bytes en total

struct metadata {
  bit<64> feature1;
  bit<64> feature2;
  bit<64> feature3;
  bit<64> feature4;
  bit<64> feature5;
  bit<64> feature6;
  bit<64> feature7;
  bit<64> feature8;
  bit<64> feature9;
  bit<64> feature10;
  bit<64> feature11;
  bit<64> feature12;

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
  bit<48> syn_time;
  bit<32> spkts;
  bit<8> sttl;
  bit<8> dttl;
  bit<48> tcprtt;
  bit<32> dbytes;

  bit<32> dpkts;

  bit<1> is_first;
  bit<1> is_hash_collision;
  bit<1> first_ack;

  bit<8> state;
  bit<8> ct_state_ttl;
  bit<48> dur;

  bit<48> time_first_pkt;
}

struct headers {
  ethernet_t   ethernet;
  ipv4_t       ipv4;
  tcp_t        tcp;
  udp_t        udp;
  features_t   features;
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

  register<bit<1>>(MAX_REGISTER_ENTRIES) reg_first_ack;

  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dpkts;
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dbytes;//src dst byte count
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_sbytes;//src dst byte count


  register<bit<48>>(MAX_REGISTER_ENTRIES) reg_syn_time;

  //Registers for identifying the flow more apart from hash we may use source port
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_spkts;//src dst pkt count
  register<bit<32>>(MAX_REGISTER_ENTRIES) reg_srcip;
  register<bit<16>>(MAX_REGISTER_ENTRIES) reg_srcport;
  register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dstport;
  register<bit<48>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;
  register<bit<48>>(MAX_REGISTER_ENTRIES) reg_tcprtt;

  //Store some statistics for the experiment
  counter(10, CounterType.packets) counter;

  action init_register() {
    //intialise the registers to 0
    reg_srcip.write(meta.register_index, 0);
    reg_srcport.write(meta.register_index, 0);
    reg_dstport.write(meta.register_index, 0);
    reg_ttl.write(meta.register_index, 0);
    reg_dttl.write(meta.register_index, 0);
    reg_dpkts.write(meta.register_index, 0);
    reg_tcprtt.write(meta.register_index, 0);
    reg_syn_time.write(meta.register_index, 0);
    reg_dbytes.write(meta.register_index, 0);
    reg_sbytes.write(meta.register_index, 0);
    reg_spkts.write(meta.register_index, 0);
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

  action ipv4_forward(egressSpec_t port) {
    standard_metadata.egress_spec = port;
    //hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    //hdr.ethernet.dstAddr = dstAddr;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
  }

  action init_features(){
    meta.feature1 = (bit<64>)meta.sttl;
    meta.feature2 = (bit<64>)meta.ct_state_ttl;
    meta.feature3 = (bit<64>)meta.dttl;
    meta.feature4 = (bit<64>)(meta.sbytes * (meta.spkts - 1) * 8);
    meta.feature5 = (bit<64>)meta.dpkts;
    meta.feature6 = (bit<64>)meta.dbytes;
    meta.feature7 = (bit<64>)meta.sbytes;
    meta.feature8 = (bit<64>)(meta.dbytes * (meta.dpkts - 1) * 8)
    meta.feature10 = (bit<64>)meta.tcprtt;
    meta.feature11 = (bit<64>)meta.dstport;
    meta.feature12 = (bit<64>)meta.dur;
  }

  action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<64> threshold) {
    bit<64> feature = 0;
    bit<64> th = threshold;
    bit<16> f = f_inout + 1;

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
      th = th*(bit<64>)meta.dur * (bit<64>)meta.sbytes;
    }
    else if (f==5){
      feature = meta.feature5;
    }
    else if (f==6){
      feature = meta.feature6;
      th = th * (bit<64>) meta.dpkts;
    }
    else if (f==7){
      feature = meta.feature7;
      th = th * (bit<64>) meta.dpkts;
    }
    else if (f==8){
      feature = meta.feature8 * 1000000;
      th = th * (bit<64>)meta.dur * (bit<64>)meta.sbytes;
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
    hdr.features.setValid();

    hdr.features.feature1 = meta.feature1;
    hdr.features.feature2 = meta.feature2;
    hdr.features.feature3 = meta.feature3;
    hdr.features.feature4 = 0;
    hdr.features.feature5 = meta.feature5;
    hdr.features.feature6 = meta.feature6;
    hdr.features.feature7 = meta.feature7;
    hdr.features.feature8 = meta.feature8;
    hdr.features.feature9 = 0;
    hdr.features.feature10 = meta.feature10;
    hdr.features.feature11 = meta.feature11;
    hdr.features.feature12 = meta.feature12;

    hdr.features.dur     = (bit<64>)meta.dur;
    hdr.features.sbytes  = (bit<64>)meta.sbytes;
    hdr.features.dpkts   = (bit<64>)meta.dpkts;
    hdr.features.spkts   = (bit<64>)meta.spkts;
    hdr.features.malware = 0;
    hdr.features.is_first = meta.is_first;

    standard_metadata.egress_spec = CPU_PORT;
  }

  action SetClass(bit<16> node_id, bit<16> class, bit<8> certainty) {
    meta.node_id = node_id;
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

    if (meta.direction == 0){
      counter.count(0);
    } else {
      counter.count(1);
    };

    meta.class = CLASS_NOT_SET;

    set_ingress_timestamp();

    //TODO: if (hdr.packet_out.isValid()) meant for packets from controller

    if (hdr.ipv4.isValid()) {

      if (hdr.ipv4.protocol == 1 || hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17) {//We treat only TCP or UDP packets (and ICMP for testing)
        if (meta.direction == 1) {
          if (hdr.ipv4.protocol == 6) {
            get_register_index_tcp();
            meta.srcport = hdr.tcp.srcPort;
            meta.dstport = hdr.tcp.dstPort;
          }
          else {
            get_register_index_udp();
            meta.srcport = hdr.udp.srcPort;
            meta.dstport = hdr.udp.dstPort;
          }

          //read_reg_to_check_collision srcip, srcport, dstport
          reg_srcip.read(meta.srcip, meta.register_index);
          reg_srcport.read(meta.srcport, meta.register_index);
          reg_dstport.read(meta.dstport, meta.register_index);

          if (meta.srcip == 0) {//It was an empty register
            meta.is_first = 1;
          }
          else if (meta.srcip != hdr.ipv4.srcAddr || meta.srcport != meta.srcport
              || meta.dstport != meta.dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {
              meta.time_first_pkt = standard_metadata.ingress_global_timestamp;
              reg_time_first_pkt.write((bit<32>)meta.register_index, meta.time_first_pkt);
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.srcAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.dstport);
            }

            reg_spkts.read(meta.spkts, (bit<32>)meta.register_index);
            meta.spkts = meta.spkts + 1;
            reg_spkts.write((bit<32>)meta.register_index, meta.spkts);

            meta.sttl = hdr.ipv4.ttl;
            reg_ttl.write((bit<32>)meta.register_index, meta.sttl);

            reg_dttl.read(meta.dttl, (bit<32>)meta.register_index);

            //read_sbytes also used for sload
            reg_sbytes.read(meta.sbytes, (bit<32>)meta.register_index);
            meta.sbytes = meta.sbytes + standard_metadata.packet_length - 14;
            reg_sbytes.write((bit<32>)meta.register_index, meta.sbytes);

            // tcprtt
            //SYN TIME
            if ((hdr.tcp.ack != (bit<1>)1)&&(hdr.tcp.syn == (bit<1>)1)) {//this is a SYN
              reg_syn_time.write((bit<32>)meta.register_index, standard_metadata.ingress_global_timestamp);
            }
            //ACK + SYN time
            else if ((hdr.tcp.ack == (bit<1>)1)&&(hdr.tcp.syn != (bit<1>)1)) {//this is an ACK
              reg_first_ack.read(meta.first_ack, (bit<32>)meta.register_index);

              if (meta.first_ack == 0) {
                //sum of synack(SYN to SYN_ACK time) and ackdat(SYN_ACK to ACK time)
                reg_syn_time.read(meta.syn_time, (bit<32>)meta.register_index);

                if (meta.syn_time > 0) {//There was a syn before
                  meta.tcprtt = standard_metadata.ingress_global_timestamp - meta.syn_time;
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
            meta.srcport = hdr.tcp.dstPort;//its inverse
            meta.dstport = hdr.tcp.srcPort;
          }
          else {
            get_register_index_inverse_udp();
            meta.srcport = hdr.udp.dstPort;
            meta.dstport = hdr.udp.srcPort;
          }

          meta.register_index = meta.register_index_inverse;

          //read_reg_to_check_collision srcip, srcport, dstport
          reg_srcip.read(meta.srcip, meta.register_index);
          reg_srcport.read(meta.srcport, meta.register_index);
          reg_dstport.read(meta.dstport, meta.register_index);
          if (meta.srcip == 0) {//It was an empty register
            meta.is_first = 1;
          }
          else if (meta.srcip != hdr.ipv4.dstAddr || meta.srcport != meta.srcport
              || meta.dstport != meta.dstport) {
            //Hash collision!
            //TODO handle hash collisions in a better way!
            meta.is_hash_collision = 1;
          }

          if (meta.is_hash_collision == 0) {
            if (meta.is_first == 1) {//shouldn't happen!
              reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.dstAddr);
              reg_srcport.write((bit<32>)meta.register_index, meta.srcport);
              reg_dstport.write((bit<32>)meta.register_index, meta.dstport);

            }

            reg_dpkts.read(meta.dpkts, (bit<32>)meta.register_index);
            meta.dpkts = meta.dpkts + 1;
            reg_dpkts.write((bit<32>)meta.register_index, meta.dpkts);

            reg_dbytes.read(meta.dbytes, (bit<32>)meta.register_index);
            meta.dbytes = meta.dbytes + standard_metadata.packet_length - 14;
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
          meta.dur = standard_metadata.ingress_global_timestamp - meta.time_first_pkt;

          calc_state();
          calc_ct_state_ttl();

          init_features();

          //start with parent node of decision tree
          meta.node_id = 0;
          meta.prevFeature = 0;
          meta.isTrue = 1;

          //TODO if malware

          level1.apply();
          if (meta.class == CLASS_NOT_SET) {
            level2.apply();
            if (meta.class == CLASS_NOT_SET) {
              level3.apply();
              if (meta.class == CLASS_NOT_SET) {
                level4.apply();
                if (meta.class == CLASS_NOT_SET) {
                  level5.apply();
                }
              }
            }
          }
        }//hash collision check
      }

      if (meta.class == SEND_TO_ORACLE){
        send_to_oracle();
      }else{
        if(meta.class == 0) {
          standard_metadata.egress_spec = 771;
          hdr.ipv4.ecn = 0;
          counter.count(2);
        } else {
          standard_metadata.egress_spec = 770;
          hdr.ipv4.ecn = 1;
          counter.count(3);
        }

        hdr.ipv4.dstAddr = (bit<32>) standard_metadata.ingress_global_timestamp;
        hdr.ipv4.srcAddr = (bit<32>) meta.time_first_pkt;
        hdr.ipv4.dSField = (bit<6>) meta.dur;

        //ipv4_exact.apply();
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
