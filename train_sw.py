#!/usr/bin/env python3

# inspired from https://github.com/ksingh25/SwitchTree

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import sklearn as sk
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor
from sklearn.feature_selection import SelectFromModel
from sklearn.tree import _tree
import math
from sklearn import tree
from sklearn.tree import export_text
import json
import pickle as pickle
import csv
from export_rules_sw import ExportRulesP4

csv_file_name_for_retrain = "ml_data/predicted_labels_oracle.csv"

class TrainSwitch():

    def __init__(self) -> None:

        #############################################
        # - intial train of the switch
        # - generate the rules corresponding to the trained model
        #############################################
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

        # reduced data train for switch - 50% 
        self.data_train, data_test, self.train_labels, test_labels = train_test_split(data_train, train_label_label, test_size = 0.5, random_state = 50)

        # train the ML model
        # bootstrap = False to let the samples values be the real ones
        self.rf = RandomForestClassifier(n_estimators = 1, n_jobs=1, random_state=0, max_depth=4, bootstrap=False)

        self.rf.fit(self.data_train, self.train_labels)
        # for tree_in_forest in self.rf.estimators_:
        #     plt.figure(figsize=(15,15))
        #     tree.plot_tree(tree_in_forest,class_names=True, fontsize=8)
        #     plt.show()

        # save the training data from the switch for retraining (for adding data, replacing it, etc.)
        # comment to only use new generated data when retraining
        with open(csv_file_name_for_retrain, "a") as save_labels_for_retrain:
            writer = csv.writer(save_labels_for_retrain)
            data_for_retrain = np.column_stack((self.data_train, self.train_labels))
            for x in data_for_retrain:
                writer.writerow(x)


        # generate files with the trained RF
        self.export_rules()
        # generate rules from these files
        self.exp_rules_sw = ExportRulesP4()
        self.exp_rules_sw.generate_rules()

    def retrain(self):

        #############################################
        # - retrain of the switch
        # - with data from the predicted labels by the oracle
        # - generate the rules corresponding to the trained model
        #############################################
        # TODO: retrain with different data
        data_train = pd.read_csv('ml_data/predicted_labels_oracle.csv')
        data_train.shape

        train_label_label = np.array(data_train['Label'])
        data_train = data_train.drop('Label', axis = 1)

        # X = data_train.select_dtypes(include=[object])
        # #One hot encoding
        # X = pd.get_dummies(X)
        # X.shape

        # #combine the data
        # data_wo_X = data_train
        # data_wo_X.shape

        # frames = [data_wo_X, X]
        # data_train = pd.concat(frames, axis=1)
        # del data_wo_X
        # del X
        # del frames

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
        lencoder.fit(train_label_label)
        train_label_label = lencoder.transform(train_label_label)

        # new data train for the switch
        self.data_train, data_test, self.train_labels, test_labels = train_test_split(data_train, train_label_label, test_size = 0.0000000000000001, random_state = 50)

        # train the ML model
        # bootstrap = False to let the samples values be the real ones
        self.rf = RandomForestClassifier(n_estimators = 1, n_jobs=1, random_state=0, max_depth=4, bootstrap=False)

        self.rf.fit(self.data_train, self.train_labels)

        # generate files with the trained RF
        self.export_rules()
        # generate rules from these files
        self.exp_rules_sw = ExportRulesP4()
        self.exp_rules_sw.generate_rules()


    def export_rules(self):
        i_tree = 0
        for tree_in_forest in self.rf.estimators_:
            with open('ml_data/tree_' + str(i_tree) + '.dot', 'w') as my_file:
                my_file = tree.export_graphviz(tree_in_forest, out_file = my_file)
                r = export_text(tree_in_forest)
                self.cant_hojas = tree_in_forest.get_n_leaves()
                self.probs = [0]*self.cant_hojas
                self.hojas = [0]*self.cant_hojas
                self.leaf = 0
                self.calc_probs(tree_in_forest)
                with open('ml_data/probs_'+str(i_tree)+'.json', 'w') as filehandle:
                    json.dump(self.probs,filehandle)
            i_tree = i_tree + 1
        filename = 'ml_data/final_rf_model.sav'
        pickle.dump(self.rf, open(filename, 'wb'))


    # obtener las hojas del arbol
    def func_hojas(self, tree_clf):
        def hoja(tree, node):
            # global leaf
            # global hojas
            tree_ = tree.tree_
            if tree_.feature[node] != _tree.TREE_UNDEFINED:
                hoja(tree, tree_.children_left[node])
                hoja(tree, tree_.children_right[node])
            else:
                self.hojas[self.leaf] = node
                self.leaf = self.leaf + 1

        hoja(tree_clf, 0)

    def calc_probs(self, tree_clf):
        self.func_hojas(tree_clf)
        for i in range(self.cant_hojas):
            tree_ = tree_clf.tree_
            samples_hoja = tree_.n_node_samples[self.hojas[i]]
            values = tree_.value[self.hojas[i],0]
            samples_label = values.max()
            self.probs[i] = math.ceil((samples_label/samples_hoja)*100)

