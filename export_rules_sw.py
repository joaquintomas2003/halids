import numpy as np
import pickle
import json
import math
from sklearn import tree
from sklearn.tree import _tree
from sklearn.tree import DecisionTreeClassifier


class ExportRulesP4():
    def __init__(self) -> None:
        pass

    def open_files(self):
        filename = 'final_rf_model.sav'
        self.rf = pickle.load(open(filename, 'rb'))

        f = open('probs_0.json')
        self.probs_leafs = json.load(f)

        self.i_tree = 0
        self.global_leaf = 0
        self.global_id = 0

    def export_p4(self, decision_tree):
        f = open("rules.txt", "w")
        tree_ = decision_tree.tree_
        class_names = decision_tree.classes_

        def _add_leaf(value, class_name, indent, prevfeature, result, depth, previous_id):
            current_id = self.global_id
            table_name = f"ingress::level{depth}"
            rule_name = f"rule{self.global_id}_level{depth}"

            match_dict = {
                "ingress::scalars.metadata@node_id": {"value": str(previous_id)},
                "ingress::scalars.metadata@isTrue": {"value": str(result)},
                "ingress::scalars.metadata@prevFeature": {"value": str(prevfeature)}
            }
            action_dict = {
                "type": "ingress::SetClass",
                "data": {
                    "node_id": {"value": str(current_id)},
                    "class": {"value": str(int(float(class_name)))},
                    "certainty": {"value": str(self.probs_leafs[self.global_leaf])}
                }
            }

            text = f"/opt/netronome/p4/bin/rtecli tables add " \
                   f"--table-name {table_name} " \
                   f"--rule {rule_name} " \
                   f"--match '{json.dumps(match_dict)}' " \
                   f"--action '{json.dumps(action_dict)}'"

            f.write(text + "\n")
            self.global_leaf += 1

        def print_tree_recurse(node, depth, prevfeature, result, previous_id):
            self.global_id += 1
            current_id = self.global_id

            value = decision_tree.tree_.value[node][0]
            class_name = np.argmax(value)

            if decision_tree.tree_.feature[node] != _tree.TREE_UNDEFINED:
                name = str(decision_tree.tree_.feature[node])
                threshold = float(decision_tree.tree_.threshold[node])

                # Crear comando para nodo intermedio
                table_name = f"ingress::level{depth}"
                rule_name = f"rule{self.global_id}_level{depth}"
                match_dict = {
                    "ingress::scalars.metadata@node_id": {"value": str(previous_id)},
                    "ingress::scalars.metadata@isTrue": {"value": str(result)},
                    "ingress::scalars.metadata@prevFeature": {"value": str(prevfeature)}
                }

                if int(name) in [9, 11]:  # dur o tcprtt (multiplicar por 1e6)
                    threshold_value = int(1000000.0 * threshold)
                else:
                    threshold_value = int(threshold)

                action_dict = {
                    "type": "ingress::CheckFeature",
                    "data": {
                        "threshold": {"value": str(threshold_value)},
                        "node_id": {"value": str(current_id)},
                        "f_inout": {"value": str(name)}
                    }
                }

                text = f"/opt/netronome/p4/bin/rtecli tables add " \
                       f"--table-name {table_name} " \
                       f"--rule {rule_name} " \
                       f"--match '{json.dumps(match_dict)}' " \
                       f"--action '{json.dumps(action_dict)}'"

                f.write(text + "\n")

                # Recurse left (<= threshold) → isTrue = 1
                print_tree_recurse(decision_tree.tree_.children_left[node], depth + 1, name, 1, current_id)
                # Recurse right (> threshold) → isTrue = 0
                print_tree_recurse(decision_tree.tree_.children_right[node], depth + 1, name, 0, current_id)

            else:
                # Nodo hoja
                _add_leaf(value, class_name, "", prevfeature, result, depth, previous_id)

        print_tree_recurse(0, 1, 0, 1, self.global_id)
        f.close()

    def generate_rules(self):
        self.open_files()
        for tree_in_forest in self.rf.estimators_:
            self.i_tree += 1
            self.export_p4(tree_in_forest)
