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

oracle = Oracle()
oracle.setUp()
