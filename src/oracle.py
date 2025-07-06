from scapy.all import sniff, Raw, sendp, Raw, Ether, TCP
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import sklearn as sk
from sklearn import preprocessing
from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor
from sklearn.feature_selection import SelectFromModel
import csv
import subprocess
import sys
from train_sw import TrainSwitch

csv_file_name_for_retrain = "ml_data/predicted_labels_oracle.csv"

def get_u64(payload, offset, length=8):
    return int.from_bytes(payload[offset:offset+length], byteorder="big")

def build_packet_out_header(packet_type, opcode, flow_hash, label, malware, is_first, reserved=0):
    header = b''

    header += int(packet_type).to_bytes(1, 'big')
    header += int(opcode).to_bytes(1, 'big')
    header += int(flow_hash).to_bytes(4, 'big')
    header += int(label).to_bytes(2, 'big')
    last_byte = ((malware & 0x1) << 7) | ((is_first & 0x1) << 6) | (reserved & 0x3F)
    header += last_byte.to_bytes(1, 'big')

    return header  # total: 9 bytes

def send_packet_out(original_pkt, flow_hash, predicted_label, malware, is_first):
    packet_type = 2
    opcode = 2

    pkt_out_header = build_packet_out_header(
        packet_type=packet_type,
        opcode=opcode,
        flow_hash=flow_hash,
        label=predicted_label,
        malware=malware,
        is_first=is_first,
        reserved=0
    )

    payload = bytes(original_pkt)

    final_payload = pkt_out_header + payload
    if len(final_payload) > 1500:
            print(f"[!] Packet size {len(final_payload)} exceeds MTU 1500. Packet not sent.")
            return

    out_pkt = Raw(load=final_payload)
    sendp(out_pkt, iface="vf0_0", verbose=False)

class Oracle():
    CPU_PORT = 510
    received_packets = 0
    cant_retrain = 0

    # opcode
    NO_OP                    = '0'
    SEND_FEATURES            = '1'
    RCV_LABEL                = '2'


    def __init__(self) -> None:
        #############################################
        ############# TRAIN THE ORACLE ##############
        #############################################
        self.predicted_0_count = 0
        self.predicted_1_count = 0

        data_train = pd.read_csv('ml_data/datos_limpios.csv')
        data_train.shape

        #Separate labels/ground truth
        train_label_attack_category = np.array(data_train['attack_cat'])
        train_label_label = np.array(data_train['Label'])
        train_label_attack_category_orig = train_label_attack_category

        #Remove labels from data
        data_train = data_train.drop('attack_cat', axis = 1)
        data_train = data_train.drop('Label', axis = 1)

        X = data_train.select_dtypes(include=[object])
        X = X.drop('srcip', axis=1)
        X = X.drop('dstip', axis=1)
        #One hot encoding
        X = pd.get_dummies(X)
        X.shape

        #combine the data
        data_wo_X = data_train
        data_wo_X = data_wo_X.drop('srcip', axis=1)
        data_wo_X = data_wo_X.drop('dstip', axis=1)
        data_wo_X = data_wo_X.drop('proto', axis=1)
        data_wo_X = data_wo_X.drop('state', axis=1)
        data_wo_X = data_wo_X.drop('service', axis=1)

        data_wo_X.shape
        frames = [data_wo_X, X]
        data_train = pd.concat(frames, axis=1)
        del data_wo_X
        del X
        del frames

        #use only top features
        data_top = data_train[['sttl', 'ct_state_ttl', 'dttl',
                               'Sload', 'Dpkts', 'dmeansz', 'sbytes', 'Dload', 'smeansz',
                               'tcprtt', 'dsport', 'dur']]
        data_train = data_top

        # save max values from some features to approximate during retrain
        max_values = data_train.max()
        self.max_sload = max_values["Sload"]
        self.max_dmeansz = max_values["dmeansz"]
        self.max_dload = max_values["Dload"]
        self.max_smeansz = max_values["smeansz"]

        #get feature names
        feature_list = list(data_train.columns)
        #convert to numpy array
        data_train = np.array(data_train)

        #transform string labels to values
        lencoder = preprocessing.LabelEncoder()
        lencoder.fit(train_label_attack_category)
        list(lencoder.classes_)
        train_label_attack_category = lencoder.transform(train_label_attack_category)
        lencoder.fit(train_label_label)
        train_label_label = lencoder.transform(train_label_label)

        # The oracle has all the data
        # can change the test_size for testing
        data_train, data_test, train_labels, test_labels = train_test_split(data_train, train_label_label, test_size=0.00000000001, random_state = 50)

        # ML model
        # bootstrap = False to let the samples values be the real ones
        # n_estimators: number of DT in RF
        self.rf = RandomForestClassifier(n_estimators = 100, n_jobs=1, random_state=0, max_depth=14, bootstrap=False)

        self.rf.fit(data_train, train_labels)
        # for tree_in_forest in self.rf.estimators_:
        #     plt.figure(figsize=(15,15))
        #     tree.plot_tree(tree_in_forest,class_names=True, fontsize=8)
        #     plt.show()
        # CSV for retraining of the switch
        with open(csv_file_name_for_retrain, "w") as save_labels_for_retrain:
            # erase csv
            save_labels_for_retrain.truncate()
            writer = csv.writer(save_labels_for_retrain)
            writer.writerow(['sttl', 'ct_state_ttl', 'dttl', 'Sload', 'Dpkts', 'dmeansz', 'sbytes', 'Dload', 'smeansz', 'tcprtt', 'dsport', 'dur', 'Label'])

    def setUp(self):
        # First, we do the initial train of the switch
        self.train_sw = TrainSwitch()
        subprocess.call(['sh', './add_entries.sh'])
        print("Switch trained - rules loaded")

    def predict_label(self, pkt):
        Oracle.received_packets += 1
        print(f"Received packet #{Oracle.received_packets}")

        if TCP not in pkt:
            print("Non-TCP packet received, skipping.")
            return

        payload = bytes(pkt[TCP].payload)

        if not payload:
            print("No payload found.")
            return

        payload_base = 0
        if len(payload) == 144:
            payload_base = 9
            payload = payload[payload_base:]

        if len(payload) < payload_base + 135:
            print(f"Payload too short ({len(payload)} bytes). Expected 136.")
            return

        print(f"length {len(payload)}")
        packet_type = get_u64(payload, 0, 1)
        print(f"Packet type: {packet_type}")
        opcode = get_u64(payload, 1, 1)
        print(f"Opcode: {opcode}")
        flow_hash = get_u64(payload, 2, 4)

        base = 6 # 6 bytes from packet_type, opcode and flow_hash
        dur_value = get_u64(payload, base + 96)
        sbytes_value = get_u64(payload, base + 104)
        dpkts_value = get_u64(payload, base + 112)
        spkts_value = get_u64(payload, base + 120)

        # Boolean flags (malware and is_first) packed in last byte
        flag_byte = payload[base + 128]
        malware = (flag_byte >> 7) & 0x1  # first bit
        is_first = (flag_byte >> 6) & 0x1  # second bit

        features_fit = [0] * 12
        features_train = [0] * 12
        max_int = sys.maxsize

        for i in range(12):
            offset = base + i * 8
            orig_value = get_u64(payload, offset)
            retrain_value = orig_value

            if i == 3:  # Sload
                if dur_value == 0 or sbytes_value == 0:
                    if orig_value != 0:
                        orig_value = max_int
                        retrain_value = self.max_sload
                else:
                    orig_value = orig_value * 1e6 / (dur_value * sbytes_value)
                    retrain_value = orig_value
            elif i == 5:  # dmeansz
                if dpkts_value == 0:
                    if orig_value != 0:
                        orig_value = max_int
                        retrain_value = self.max_dmeansz
                else:
                    orig_value = orig_value / dpkts_value
                    retrain_value = orig_value
            elif i == 7:  # Dload
                if dur_value == 0 or sbytes_value == 0:
                    if orig_value != 0:
                        orig_value = max_int
                        retrain_value = self.max_dload
                else:
                    orig_value = orig_value * 1e6 / (dur_value * sbytes_value)
                    retrain_value = orig_value
            elif i == 8:  # smeansz
                if spkts_value == 0:
                    if orig_value != 0:
                        orig_value = max_int
                        retrain_value = self.max_smeansz
                else:
                    orig_value = orig_value / spkts_value
                    retrain_value = orig_value
            elif i == 9 or i == 11:  # tcprtt, dur
                orig_value = orig_value / 1e6
                retrain_value = orig_value

            features_fit[i] = orig_value
            features_train[i] = retrain_value

        prediction = self.rf.predict([features_fit])[0]

        if prediction == 1:
            self.predicted_1_count += 1
        elif prediction == 0:
            self.predicted_0_count += 1

        print(f"Predicted label: {prediction}, Malware: {malware}, First: {is_first}")
        print(f"Total predicted 0s: {self.predicted_0_count}, 1s: {self.predicted_1_count}")

        send_packet_out(pkt, flow_hash, int(prediction), malware, is_first)

        with open('ml_data/predicted_labels_oracle.csv', 'a') as f:
            writer = csv.writer(f)
            writer.writerow(features_train + [prediction])

        # Retrain
        packets_retrain = 100
        if Oracle.received_packets > packets_retrain:
            Oracle.cant_retrain += 1
            self.train_sw.retrain()

            # update max
            self.max_sload = max(self.max_sload, self.train_sw.max_sload)
            self.max_dmeansz = max(self.max_dmeansz, self.train_sw.max_dmeansz)
            self.max_dload = max(self.max_dload, self.train_sw.max_dload)
            self.max_smeansz = max(self.max_smeansz, self.train_sw.max_smeansz)

            subprocess.call(['sh', './add_entries.sh'])
            print(f"Switch retrained {Oracle.cant_retrain} times")
            Oracle.received_packets = 0

oracle = Oracle()
oracle.setUp()

print("Escuchando paquetes en vf0_0...")
sniff(iface="vf0_0", prn=oracle.predict_label, store=0)
