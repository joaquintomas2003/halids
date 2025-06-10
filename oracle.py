from scapy.all import sniff, Raw
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

csv_file_name_for_retrain = "predicted_labels_oracle.csv"

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

        data_train = pd.read_csv('datos_limpios.csv')
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
        Oracle.received_packets = Oracle.received_packets + 1
        print("received packets:", Oracle.received_packets)
        # extra data needed to calculate features
        metadata_temp = pkt.packet.metadata[15]
        dur_value = int.from_bytes(metadata_temp.value, byteorder="big")
        metadata_temp = pkt.packet.metadata[16]
        sbytes_value = int.from_bytes(metadata_temp.value, byteorder="big")
        metadata_temp = pkt.packet.metadata[17]
        dpkts_value = int.from_bytes(metadata_temp.value, byteorder="big")
        metadata_temp = pkt.packet.metadata[18]
        spkts_value = int.from_bytes(metadata_temp.value, byteorder="big")
        # extract features from received packet
        features_fit = [0] * 12
        features_train = [0] * 12
        max_int = sys.maxsize
        for metadata in pkt.packet.metadata:
            if (metadata.metadata_id == 3):
                # metadata with flow hash
                flow_hash = int.from_bytes(metadata.value, byteorder="big")
                flow_hash = str(flow_hash)
            feature_id = metadata.metadata_id - 4
            if (feature_id>-1 and feature_id<12): 
                # save received features
                orig_value = int.from_bytes(metadata.value, byteorder="big")
                retrain_value = orig_value
                if feature_id == 3: # id = 4 (sload feature)
                    if(dur_value == 0 or sbytes_value == 0):
                        if (orig_value != 0):
                            orig_value = max_int # make it bigger than the threshold
                            retrain_value = self.max_sload
                    else:
                        orig_value = orig_value * 1000000
                        orig_value = orig_value / (dur_value*sbytes_value)
                        retrain_value = orig_value
                if feature_id == 5: # id = 6 (dmeansz feature)
                    if(dpkts_value == 0):
                        if (orig_value != 0):
                            orig_value = max_int # make it bigger than the threshold
                            retrain_value = self.max_dmeansz
                    else:
                        orig_value = orig_value / dpkts_value
                        retrain_value = orig_value
                if feature_id == 7: # id = 8 (dload feature)
                    if(dur_value == 0 or sbytes_value == 0):
                        if (orig_value != 0):
                            orig_value = max_int # make it bigger than the threshold
                            retrain_value = self.max_dload
                    else:
                        orig_value = orig_value * 1000000
                        orig_value = orig_value / (dur_value*sbytes_value)
                        retrain_value = orig_value
                if feature_id == 8: # id = 9 (smeansz feature)
                    if(spkts_value == 0):
                        if (orig_value != 0):
                            orig_value = max_int # make it bigger than the threshold
                            retrain_value = self.max_smeansz
                    else:
                        orig_value = orig_value / spkts_value
                        retrain_value = orig_value
                if feature_id == 9 or feature_id == 11: # id = 10 (tcprrt) id = 12 (dur)
                    orig_value = orig_value / int(1000000.0)
                    retrain_value = orig_value
                features_fit[feature_id] = orig_value
                features_train[feature_id] = retrain_value
        self.packetOut.payload = pkt.packet.payload
        self.packetOut.metadata["packet_type"] = Oracle.PACKET_OUT
        self.packetOut.metadata["opcode"] = Oracle.RCV_LABEL
        self.packetOut.metadata["flow_hash"] = flow_hash
        predicted_label = self.rf.predict([features_fit])
        self.packetOut.metadata["label"] = str(predicted_label[0])
        malware_temp = pkt.packet.metadata[19]
        malware = int.from_bytes(malware_temp.value, byteorder="big")
        self.packetOut.metadata["malware"] = str(malware)
        is_first_temp = pkt.packet.metadata[20]
        is_first = int.from_bytes(is_first_temp.value, byteorder="big")
        self.packetOut.metadata["is_first"] = str(is_first)
        self.packetOut.metadata["reserved"] = '0'
        self.packetOut.send()
        # every time the oracle predicts a label, we save it
        with open('predicted_labels_oracle.csv', 'a') as save_labels_for_retrain:
            writer = csv.writer(save_labels_for_retrain)
            row = [0] * 13
            # features from received pkt - with modifications/approximations
            for i in range(12):
                row[i] = features_train[i]
            # label predicted for pkt
            row[12] = str(predicted_label[0])
            # save decision in csv
            writer.writerow(row) 
        # erase csv and retrain
        # change number of packets for retrain
        packets_retrain = 100000000000000000000
        if (Oracle.received_packets > packets_retrain):
            Oracle.cant_retrain = Oracle.cant_retrain + 1
            self.train_sw.retrain()
            # if new max appears at retrain, save it 
            if (self.max_sload < self.train_sw.max_sload):
                self.max_sload = self.train_sw.max_sload
            if (self.max_dmeansz < self.train_sw.max_dmeansz):
                self.max_dmeansz = self.train_sw.max_dmeansz
            if (self.max_dload < self.train_sw.max_dload):
                self.max_dload = self.train_sw.max_dload
            if (self.max_smeansz < self.train_sw.max_smeansz):
                self.max_smeansz = self.train_sw.max_smeansz
            subprocess.call(['sh', './add_entries.sh'])
            print("Switch retrained for", Oracle.cant_retrain, "time")
            Oracle.received_packets = 0
            # uncomment this to erase the saved labels 
            # with open(csv_file_name_for_retrain, "w") as save_labels_for_retrain:
            #     # erase csv
            #     save_labels_for_retrain.truncate()
            #     writer = csv.writer(save_labels_for_retrain)
            #     writer.writerow(['sttl', 'ct_state_ttl', 'dttl', 'Sload', 'Dpkts', 'dmeansz', 'sbytes', 'Dload', 'smeansz', 'tcprtt', 'dsport', 'dur', 'Label']) 
            
            # uncomment this to replace rows from the saved labels
            # erasing first X rows - "replacing" them with oracle decisions
            df = pd.read_csv(csv_file_name_for_retrain)
            for i in range(0,4999):
                df = df.drop(i)
            df.to_csv(csv_file_name_for_retrain, index=False)

oracle = Oracle()
oracle.setUp()
