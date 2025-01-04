import random
import time
import numpy as np
from pandas import read_csv
from sklearn.utils import shuffle
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.ensemble import VotingClassifier, StackingClassifier, RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

from sklearn.preprocessing import LabelEncoder

""" # Sets random seed to increase repeatability
random.seed(23)
np.random.seed(23) """

def ip_to_binary(ip):
    """
    Convert an IP address to a binary string composed of its four octets.
    :param ip: str, IP address (e.g., '192.168.1.1')
    :return: str, binary representation (e.g., '11000000101010000000000100000001')
    """
    octets = ip.split('.')  # Split the IP into octets
    binary_octets = [bin(int(octet))[2:].zfill(8) for octet in octets]  # Convert each octet to 8-bit binary
    return ''.join(binary_octets)  # Concatenate the binary strings


def current_ms() -> int:
    """
    Reports the current time in milliseconds
    :return: long int
    """
    return round(time.time() * 1000)

def from_string_to_int(string):
    return int(string, 16)

if __name__ == "__main__":
    """
    Main of the data analysis
    """
    # Load the dataset
    print("Loading dataset...")
    dataset_path = "./output/packets_training_dataset.csv" 
    testing_path = "./output/packets_testing_dataset.csv"
    dataset = read_csv(dataset_path)
    testing_dataset = read_csv(testing_path)
    
    # Initialize LabelEncoder
    encoder = LabelEncoder()

    # Fit and transform the 'protocol' column
    dataset["protocol"] = encoder.fit_transform(dataset["protocol"])
    dataset["src_ip"] = dataset["src_ip"].apply(ip_to_binary)
    dataset["checksum"] = dataset["checksum"].apply(from_string_to_int)
    dataset["flags"] = dataset["flags"].apply(from_string_to_int)
    
    # Extract labels and features
    label_obj = dataset["label"]
    data_obj = dataset.drop(columns=["label", "time", "datetime", "sniff_timestamp", "dst_ip", "transport_layer"])  # Drop non-feature columns
    data_obj, label_obj = shuffle(data_obj, label_obj, random_state = 20)  # Shuffle the dataset

    testing_dataset["protocol"] = encoder.fit_transform(testing_dataset["protocol"])
    testing_dataset["src_ip"] = testing_dataset["src_ip"].apply(ip_to_binary)
    testing_dataset["checksum"] = testing_dataset["checksum"].apply(from_string_to_int)
    testing_dataset["flags"] = testing_dataset["flags"].apply(from_string_to_int)
    
    testing_labels_obj = testing_dataset["label"]
    testing_dataset_obj = testing_dataset.drop(columns=["label", "time", "datetime", "sniff_timestamp", "dst_ip", "transport_layer"])  # Drop non-feature columns
    testing_dataset_obj, testing_labels_obj = shuffle(testing_dataset_obj, testing_labels_obj, random_state = 20)  # Shuffle the dataset
    


    # Split dataset into training and testing sets
    print("Splitting dataset into training and testing sets...")
    train_data, test_data, train_label, test_label = train_test_split(
        data_obj, label_obj, test_size=0.3, random_state=42
    )

    # Define classifiers to compare
    classifiers = [
        VotingClassifier(estimators=[
            ('lda', LinearDiscriminantAnalysis()),
            ('nb', GaussianNB()),
            ('dt', DecisionTreeClassifier())
        ]),
        StackingClassifier(estimators=[
            ('lda', LinearDiscriminantAnalysis()),
            ('nb', GaussianNB()),
            ('dt', DecisionTreeClassifier())
        ], final_estimator=RandomForestClassifier(n_estimators=10)),
        DecisionTreeClassifier(),
        GaussianNB(),
        LinearDiscriminantAnalysis(),
        KNeighborsClassifier(n_neighbors=11),
        RandomForestClassifier(n_estimators=10),
        RandomForestClassifier(n_estimators=3),
        GradientBoostingClassifier()
    ]

    # Evaluate classifiers
    print("Training and evaluating classifiers...")
    """ print(train_label)
    exit(0) """
    for clf in classifiers:
        # Training the classifier
        before_train = current_ms()
        clf = clf.fit(train_data, train_label)
        after_train = current_ms()

        # Testing the classifier
        predicted_labels = clf.predict(test_data)
        after_test = current_ms()

        # Compute metrics
        accuracy = accuracy_score(test_label, predicted_labels)
        tn, fp, fn, tp = confusion_matrix(test_label, predicted_labels).ravel()
        print(f"{clf.__class__.__name__}:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Train time: {after_train - before_train} ms")
        print(f"  Test time: {after_test - after_train} ms")
        print(f"  TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
        print(classification_report(test_label, predicted_labels, target_names=["Normal", "Anomalous"]))
        

    print("\n\n\n\n\n\nnow we try with the testing dataset directly:\n\n")
    for clf in classifiers:
        
        # Testing the classifier
        predicted_labels_2 = clf.predict(testing_dataset_obj)
        #after_test = current_ms()

        # Compute metrics
        accuracy = accuracy_score(testing_labels_obj, predicted_labels_2)
        tn, fp, fn, tp = confusion_matrix(testing_labels_obj, predicted_labels_2).ravel()
        print(f"{clf.__class__.__name__}:")
        print(f"  Accuracy: {accuracy:.4f}")
        print(f"  Train time: {after_train - before_train} ms")
        print(f"  Test time: {after_test - after_train} ms")
        print(f"  TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
        print(classification_report(testing_labels_obj, predicted_labels_2, target_names=["Normal", "Anomalous"]))
