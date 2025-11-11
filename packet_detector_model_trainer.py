import random
import time

import numpy as np

from pandas import read_csv
import pandas as pd

from sklearn.utils import shuffle
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, StackingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, f1_score, matthews_corrcoef, precision_recall_curve, average_precision_score
from sklearn.model_selection import train_test_split
from sklearn.model_selection import learning_curve
from sklearn.preprocessing import LabelEncoder
import joblib

import matplotlib.pyplot as plt


#for repeatability in training process
random.seed(986059)
np.random.seed(986059)


def current_ms() -> int:
    """
    Reports the current time in milliseconds
    :return: long int
    """
    return round(time.time() * 1000)

def from_hex_to_int(string):
    if string == None:
        return None
    else:
        try:
            integer = int(string, 16)
            return integer
        except Exception:
            return 0


def plot_metrics(clf, train_data, train_label, test_data, test_label, predicted_labels):
    """
    Function for plotting training and testing data
    """
    #---------------------------------------------------------------------------------------------------
    # Plot accuracies
    plt.figure(figsize=(10, 6))
    train_accuracy = clf.score(train_data, train_label)
    test_accuracy = accuracy_score(test_label, predicted_labels)
    plt.bar(['Training', 'Validation'], [train_accuracy, test_accuracy])
    plt.title('Model Accuracy Comparison')
    plt.ylabel('Accuracy')
    plt.ylim(0, 1)
    plt.savefig('./plots/accuracy_comparison.png')
    plt.close()

    #---------------------------------------------------------------------------------------------------
    # Feature Importance
    if hasattr(clf, 'feature_importances_'):
        plt.figure(figsize=(10, 6))
        feature_importance = pd.DataFrame({
            'feature': train_data.columns,
            'importance': clf.feature_importances_
        }).sort_values('importance', ascending=False)
        plt.bar(feature_importance['feature'], feature_importance['importance'])
        plt.title('Feature Importance')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig('./plots/eature_importance.png')
        plt.close()

    #---------------------------------------------------------------------------------------------------
    # Learning Curves
    train_sizes, train_scores, val_scores = learning_curve(
    clf, train_data, train_label, cv=5,
    n_jobs=-1, train_sizes=np.linspace(0.1, 1.0, 10))
    
    # Convert labels to binary (0,1)
    label_encoder = LabelEncoder()
    test_label_encoded = label_encoder.fit_transform(test_label)  # 'normal'=0, 'anomalous'=1

    # Precision-Recall curve with binary labels
    y_scores = clf.predict_proba(test_data)[:, 1]
    precision, recall, thresholds = precision_recall_curve(test_label_encoded, y_scores, pos_label=1)
    average_precision = average_precision_score(test_label_encoded, y_scores, pos_label=1)

    plt.figure(figsize=(10, 6))
    plt.plot(recall, precision, color='blue', lw=2,
            label=f'Precision-Recall curve (AP = {average_precision:.2f})')

    # Add markers for different thresholds
    for i in np.linspace(0, len(thresholds)-1, 5).astype(int):
        plt.plot(recall[i], precision[i], 'ro')
        plt.annotate(f'θ={thresholds[i]:.2f}', 
                    (recall[i], precision[i]),
                    xytext=(10, 10), textcoords='offset points')

    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc='best')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('./plots/precision_recall_curve.png')
    plt.close()
    
    #---------------------------------------------------------------------------------------------------
     # Plot accuracy over training examples
    plt.figure(figsize=(10, 6))
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)
    val_std = np.std(val_scores, axis=1)

    plt.plot(train_sizes, train_mean, label='Training Accuracy', color='blue')
    plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.1, color='blue')
    plt.plot(train_sizes, val_mean, label='Validation Accuracy', color='red')
    plt.fill_between(train_sizes, val_mean - val_std, val_mean + val_std, alpha=0.1, color='red')

    plt.xlabel('Training Examples')
    plt.ylabel('Accuracy')
    plt.title('Learning Curves')
    plt.legend(loc='best')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('./plots/learning_curves.png')
    plt.close()
    
    #---------------------------------------------------------------------------------------------------
    # Confusion Matrix
    cm = confusion_matrix(test_label, predicted_labels)
    plt.figure(figsize=(8, 6))

    # Calculate percentages
    cm_percentage = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

    # Plot confusion matrix
    plt.imshow(cm_percentage, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    plt.colorbar()

    # Add labels
    labels = ['Normal', 'Anomalous']
    tick_marks = np.arange(len(labels))
    plt.xticks(tick_marks, labels)
    plt.yticks(tick_marks, labels)

    # Add percentages in cells
    thresh = cm_percentage.max() / 2.
    for i, j in np.ndindex(cm_percentage.shape):
        plt.text(j, i, f'{cm_percentage[i, j]:.2%}\n({cm[i, j]})',
                horizontalalignment='center',
                color='white' if cm_percentage[i, j] > thresh else 'black')

    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig('./plots/confusion_matrix.png')
    plt.close()



if __name__ == "__main__":
    """
    Main of the data analysis
    """
    # Load the dataset
    print("Loading dataset...")
    dataset_path = "./Dataset_folder/packets_training_dataset.csv" 
    dataset = read_csv(dataset_path)

    dataset["checksum"] = dataset["checksum"].apply(from_hex_to_int)
    dataset["flags"] = dataset["flags"].apply(from_hex_to_int)
    dataset["ip_flags"] = dataset["ip_flags"].apply(from_hex_to_int)
        
    # Extract labels and features
    label_obj = dataset["label"]
    data_obj = dataset.drop(columns=["label", "time", "datetime", "time_relative", "sniff_timestamp", "src_ip", "dst_ip","transport_layer"])
    #data_obj, label_obj = shuffle(data_obj, label_obj, random_state=23) #shuffling data seems to be giving a little worst results
    
    # Split dataset into training and testing sets
    print("Splitting dataset into training and testing sets...")
    train_data, test_data, train_label, test_label = train_test_split(
        data_obj, label_obj, test_size=0.3)

    
    # Define classifiers to compare
    classifiers = [
        RandomForestClassifier(n_estimators=20),
    ] 
    
    #here we have all the other models, just ADD them above for training them too(note that the metrics data put in the plot will be relative
    # to the last trained classifier and not to RFC anymore)
    """ GradientBoostingClassifier(n_estimators=30, learning_rate=0.3, subsample=0.8),
        DecisionTreeClassifier(), #max_depth=10
        LinearDiscriminantAnalysis(),
        KNeighborsClassifier(n_neighbors=10),
        GaussianNB(),  
        StackingClassifier(estimators=[
                                     ("GB", GradientBoostingClassifier()),
                                     ("DT", DecisionTreeClassifier()),
                                     ("LDA", LinearDiscriminantAnalysis()),
                                     ("KN", KNeighborsClassifier(n_neighbors=10)),
                                     ("NB", GaussianNB()),
                                     ("RF", RandomForestClassifier(n_estimators=10))],
                                     final_estimator=RandomForestClassifier(n_estimators=10)) """
    
    results_filename = "./training_results/models_results.csv"
    with open(results_filename, 'w', newline="") as f:
                f.write("classifier,accuracy,train_time,test_time,tp,tn,fp,fn,f1_normal,f1_anomalous,mcc\n")

    # Evaluate classifiers
    print("Training and evaluating classifiers...")
    try:
        for clf in classifiers:
            # Training the classifier
            before_train = current_ms()
            clf = clf.fit(train_data, train_label)
            after_train = current_ms()

            # Testing the classifier
            predicted_labels = clf.predict(test_data)
            after_test = current_ms()

            # Compute metrics
            mcc = matthews_corrcoef(test_label, predicted_labels)
            accuracy = accuracy_score(test_label, predicted_labels)
            tn, fp, fn, tp = confusion_matrix(test_label, predicted_labels).ravel()
            f1_n = f1_score(test_label, predicted_labels, pos_label="normal")
            f1_a = f1_score(test_label, predicted_labels, pos_label="anomalous")
            
            #and print them
            print(f"{clf.__class__.__name__}:")
            print(f"  MCC: {mcc:.4f}")
            print(f"  Accuracy: {accuracy:.4f}")
            print(f"  Train time: {after_train - before_train} ms")
            print(f"  Test time: {after_test - after_train} ms")
            print(f"  TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
            with open(results_filename, 'a', newline="") as f:
                f.write(f"{clf.__class__.__name__},{accuracy},{after_train - before_train},{after_test - after_train},{tp},{tn},{fp},{fn},{f1_n},{f1_a},{mcc}\n")
            plot_metrics(clf, train_data, train_label, test_data, test_label, predicted_labels)    
            joblib.dump(clf, "training_results/packet_detector_model.pkl")
            print(classification_report(test_label, predicted_labels, target_names=["Normal", "Anomalous"])) 
    
    except Exception as e:
        print(f"Exception while training classifiers: {e}")