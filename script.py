#!/usr/bin/env python3
import sys
from pandas.core.generic import DataFrameFormatter
import os
import numpy as np
import re
import pandas as pd
import hashlib
import category_encoders as ce
import shutil
import filecmp
import warnings
from datetime import datetime
from sklearn.preprocessing import LabelEncoder
from matplotlib.axes._axes import _log as matplotlib_axes_logger

import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from matplotlib.colors import ListedColormap
from sklearn.decomposition import PCA
from sklearn.model_selection import cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.decomposition import PCA
from sklearn.svm import SVC
import sklearn.metrics as metrics

# from tqdm import tqdm_notebook as tqdm
from tqdm import tqdm
from sklearn.model_selection import GridSearchCV
import warnings

from sklearn.pipeline import Pipeline


# import matplotlib.pyplot as pyplot
from matplotlib import style

import sklearn
from sklearn import linear_model, preprocessing
from sklearn.neighbors import KNeighborsClassifier, NearestNeighbors
from sklearn.utils import shuffle

from sklearn.tree import DecisionTreeClassifier
from sklearn import tree
import seaborn as sns
from sklearn.model_selection import GridSearchCV

access_log_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(\d{2}\/[a-zA-Z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH|PROPFIND) )(.+)((http|HTTP)\/1\.(1|0)")) (\d{3}) (\d+) (["]((\-)|(.+))["]) (["](.+)["])'
access_log_folder = '\\Accesslogs'

# Check for read files #
def identicalFileExist(currentFile,completedList):
  for file in completedList:
    if filecmp.cmp(currentFile, file):
      print("File already exists. " + file + " is similar to " + currentFile + ".")
      return True
  return False
  
# DataTime Formatting for Dataframe #
def formatDateTime(df, dtformat, columnName):
  tmpdf = df
  tmpdf[columnName] = pd.to_datetime(tmpdf[columnName], format=dtformat, errors='coerce')
  tmpdf[columnName] = tmpdf[columnName].diff()
  tmpdf = tmpdf.dropna(subset=[columnName])
  tmpdf[columnName] = tmpdf[columnName].astype(np.int64)//10**6
  indexNames = tmpdf[ (tmpdf[columnName] < 0)].index
  tmpdf.drop(indexNames , inplace=True)
  return tmpdf

# NGINX access logs Convert to DataFrame #
def readAccessDataFrame(file):
  tmpdf = pd.read_csv(file,
                      sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
                      engine='python',
                      usecols=[3, 4, 5, 6, 7, 8],
                      names=['time_diff_ms', 'request', 'status', 'size', 'referer', 'user_agent'],
                      na_values='-',
                      header=None
                      )
  tmpdf = formatDateTime(tmpdf, '[%d/%b/%Y:%H:%M:%S +0000]', 'time_diff_ms')
  tmpdf.insert (6, 'technique', file[1:5])
  return tmpdf

# Reading processed logs and returning a dataframe #
def createDataFrame(inDir):
  accessLogsDF = pd.DataFrame(columns=['time_diff_ms', 'request',"status", "size", "referer","user_agent", "technique"])
  completedList = []
  for root, dirs, files in os.walk((inDir+access_log_folder), topdown=True):
      os.chdir(root)
      for file in files:
         if file.endswith(".log") and not identicalFileExist(file, completedList):
              readfile = open(file)
              content = readfile.readlines()
              if re.match(access_log_pattern, content[0]):
                tmpdf = readAccessDataFrame(file)
                accessLogsDF = accessLogsDF.append(tmpdf)
                completedList.append(file)
  accessLogsDF['size'] = accessLogsDF['size'].astype(int)
  accessLogsDF['technique'] = accessLogsDF['technique'].astype(int)
  return accessLogsDF

# Write out as .log file #
def writeAsLOG(df,file,path):
  if re.match(access_log_pattern, df[0]):
    filename = path + access_log_folder + '\\' + file
    filename = os.path.splitext(filename)[0] + ".log"
    np.savetxt(filename, df.values, fmt = "%s")

# Reading CSV as DataFrame #
def convertELKtoOrigin(file):
  df = pd.read_csv(file)
  if "event.original" in df.columns:
    tmpdf = df["event.original"]
    return tmpdf
  elif "message" in df.columns:  
    tmpdf = df.message
    return tmpdf
  return pd.DataFrame()

# Convert logs to similar format #
def readLogs(inDir):
  dir = inDir + access_log_folder
  print(dir)
  if os.path.exists(dir):
    shutil.rmtree(dir)
  os.makedirs(dir)
  for root, dirs, files in os.walk(inDir, topdown=True):
      os.chdir(root)
      for file in files:
          if "ELK" in file and file.endswith(".csv"):
            tmpdf = convertELKtoOrigin(file)
            if not tmpdf.empty:
              writeAsLOG(tmpdf,file,inDir)
          if file.endswith(".log") and root != (inDir + access_log_folder):
            readfile = open(file)
            content = readfile.readlines()
            if re.match(access_log_pattern, content[0]):
              try:
                shutil.copyfile(file, (inDir + access_log_folder + '\\' +  file))
              except shutil.SameFileError:
                pass
  return createDataFrame(inDir)

# Filtering techniques #
def filterByTechnique(df,technique):
  df['technique'] = df['technique'].apply(lambda x: 1 if x==technique else 0)
  return df

# Converting DataFrame for ____KHOI_____ machine learning #
def dataframeToList(df, target):
  x = list(zip(list(df['time_diff_ms']),list(df['request']),list(df['status']),list(df['size']),list(df['referer']),list(df['user_agent'])))
  # x = list(zip(df['time_diff_ms'],df['request'],df['status'],df['size'],df['referer'],df['user_agent']))
  y = list(target['technique'])
  # y = np.array(y)
  # y = np.reshape(y, (-1,1))
  # y = y.tolist()
  return x,y

# Split Dataframe into features and target
def splitTarget(df):
  target = df[['technique']]
  df = df.drop('technique', axis = 1)
  return df,target

# Catboost target encoder #
def catboostEncode(df,target):
  cbe_encoder = ce.cat_boost.CatBoostEncoder()
  df = cbe_encoder.fit_transform(df,target)
  return df, target

# Label Encoder #
def labelEncode(df, target):
  le = LabelEncoder()
  df['time_diff_ms'] = list(df['time_diff_ms'])
  df['request'] = le.fit_transform(list(df['request']))
  df['status'] = le.fit_transform(list(df['status']))
  df['size'] = list(df['size'].astype(int))
  df['referer'] = le.fit_transform(list(df['referer']))
  df['user_agent'] = le.fit_transform(list(df['user_agent']))
  target['technique'] = le.fit_transform(list(target['technique']))
  return df, target

def plot_contours(ax, clf, xx, yy, **params):
  z = clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
  z = z.reshape(xx.shape)
  out = ax.contourf(xx, yy, z, **params)
  return out

def make_meshgrid(x, y, h=.01):
  x_min, x_max = x.min() - 1, x.max() + 1
  y_min, y_max = y.min() - 1, y.max() + 1
  xx, yy = np.meshgrid(np.arange(x_min, x_max, h),
                       np.arange(y_min, y_max, h))
  return xx, yy

def print_score(clf, x_train, y_train, x_test, y_test, train=True):
    if train:
        pred = clf.predict(x_train)

        # generate classification report
        clf_report = pd.DataFrame(classification_report(y_train, pred, output_dict=True))
        print("Train Result:n===================================")
        print(f"Accuracy Score: {accuracy_score(y_train, pred) * 100:.2f}%")
        print("_________________________________________________")
        print(f"CLASSIFICATION REPORT:n{clf_report}")
        print("_________________________________________________")
        print(f"Confusion Matrix: n {confusion_matrix(y_train, pred)}n")
        df = pd.DataFrame(clf_report)

        # plot bar graph based on the classification report
        # bar = df.iloc[:3, :7].T.plot(kind='bar')
        bar = df.iloc[:3, :7].T
        # print("DF ILOC HERE", df.iloc[:3, :7])
        plt.show()
        # plot confusion matrix
        # plot_confusion_matrix(clf, x_train, y_train, cmap = plt.cm.Blues)
        conf_matrix = confusion_matrix(y_train, pred)
        ax = sns.heatmap(conf_matrix, annot = True, linewidth = 2, cmap = 'Blues')
        ax.set_title("Confusion matrix")
        ax.set_xlabel('Predicted label')
        ax.set_ylabel('Actual label')
        plt.show()

        return bar
        
    elif train==False:
        pred = clf.predict(x_test)

        # generate classification report
        clf_report = pd.DataFrame(classification_report(y_test, pred, output_dict=True))
        print("Test Result:n====================================")        
        print(f"Accuracy Score: {accuracy_score(y_test, pred) * 100:.2f}%")
        print("_________________________________________________")
        print(f"CLASSIFICATION REPORT:n{clf_report}")
        print("_________________________________________________")
        print(f"Confusion Matrix: n {confusion_matrix(y_test, pred)}n")
        df = pd.DataFrame(clf_report)

        # plot bar graph based on the classification report
        # bar = df.iloc[:3, :7].T.plot(kind='bar')
        bar = df.iloc[:3, :7].T
        plt.show()
        # plot confusion matrix
        # plot_confusion_matrix(clf, x_test, y_test, cmap = plt.cm.Blues)
        conf_matrix = confusion_matrix(y_test, pred)
        ax = sns.heatmap(conf_matrix, annot = True, linewidth = 2, cmap = 'Blues')
        ax.set_title("Confusion matrix")
        ax.set_xlabel('Predicted label')
        ax.set_ylabel('Actual label')
        plt.show()

        return bar

def result_1(technique, predict, ytest):
    array_result = []
    array_y_test = []

    for k in range(len(predict)):
        array_result.append(technique[predict[k]])
        array_y_test.append(technique[ytest[k]])
    return array_result, array_y_test

def result_2(dict_result, technique, data):
    overlap_count = 0
    overlap_index_array = []
    overlap_x_test = []

    missing_count = 0
    missing_index_array = []
    missing_x_test = []

    for x in range((len(list(dict_result.items())[0][1]))):
        counter = 0
        for y in range(int((len(list(dict_result.items())))/2)):
            counter += dict_result[str(technique[y]) + '_predicted'][x]
        if counter >= 2:
            overlap_count += 1
            overlap_index_array.append(x)
            overlap_x_test.append(data[x])
        elif counter == 0:
            missing_count += 1
            missing_index_array.append(x)
            missing_x_test.append(data[x])

    return overlap_count, overlap_index_array, overlap_x_test, missing_count, missing_index_array, missing_x_test

def add_dict(dict_result, key_name, value):
    dict_result[key_name] = value
    return

def models_knn(X, Y):
    global model_knn, predicted_knn, x_test, y_test, x_train, y_train, x_original_train, x_original_test, y_original_train, y_original_test
    x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.1, random_state=42)
    # x_original_train, x_original_test, y_original_train, y_original_test = sklearn.model_selection.train_test_split(X_original, Y_original, test_size=0.1, random_state=42)
    sc = StandardScaler()
    x_train = sc.fit_transform(x_train)
    x_test = sc.transform(x_test)

    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)
    
    model_knn = KNeighborsClassifier(n_neighbors=69)
    model_knn.fit(x_train, y_train)
    # accuracy = model_knn.score(x_test, y_test)
    predicted_knn = model_knn.predict(x_test)
    # print_score(model_knn, x_train, y_train, x_test, y_test, train=False)

def modelsFilter_knn(X, Y, X_original, Y_original):
    global model_knn, predicted_knn, x_test, y_test, x_train, y_train, x_original_train, x_original_test, y_original_train, y_original_test
    x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.1, random_state=42)
    x_original_train, x_original_test, y_original_train, y_original_test = sklearn.model_selection.train_test_split(X_original, Y_original, test_size=0.1, random_state=42)
    sc = StandardScaler()
    x_train = sc.fit_transform(x_train)
    x_test = sc.transform(x_test)

    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)
    
    model_knn = KNeighborsClassifier(n_neighbors=69)
    model_knn.fit(x_train, y_train)
    # accuracy = model_knn.score(x_test, y_test)
    predicted_knn = model_knn.predict(x_test)
    # print_score(model_knn, x_train, y_train, x_test, y_test, train=False)

def models_dt(x, y):    
    global model_dt, x_test, y_test, predicted_dt
    x_train, x_test, y_train, y_test =  train_test_split(x, y, test_size = 0.1, random_state = 42)

    sc_X = StandardScaler()
    x_train = sc_X.fit_transform(x_train)
    x_test = sc_X.transform(x_test)

    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)

    # from sklearn.tree import DecisionTreeClassifier
    model_dt = DecisionTreeClassifier()
    model_dt.fit(x_train,y_train)

    #prediction
    predicted_dt = model_dt.predict(x_test)

    # from sklearn import metrics
    # print('Accuracy Score:', metrics.accuracy_score(y_test,y_pred))

    # from sklearn.metrics import confusion_matrix
    # cm = confusion_matrix(y_test, y_pred)

    # Create Decision Tree classifer object
    model_dt = DecisionTreeClassifier(criterion="entropy", max_depth=3)# Train Decision Tree Classifer
    model_dt.fit(x_train,y_train)#Predict the response for test dataset
    # print_score(model_dt, x_train, y_train, x_test, y_test, train=True)
    # print_score(model_dt, x_train, y_train, x_test, y_test, train=False)

def modelsFilter_dt(x, y, X_original, Y_original):    
    global model_dt, x_test, y_test, predicted_dt, x_original_train, x_original_test, y_original_train, y_original_test
    x_train, x_test, y_train, y_test =  train_test_split(x, y, test_size = 0.1, random_state = 42)
    x_original_train, x_original_test, y_original_train, y_original_test = sklearn.model_selection.train_test_split(X_original, Y_original, test_size=0.1, random_state=42)

    sc_X = StandardScaler()
    x_train = sc_X.fit_transform(x_train)
    x_test = sc_X.transform(x_test)

    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)

    # from sklearn.tree import DecisionTreeClassifier
    model_dt = DecisionTreeClassifier()
    model_dt.fit(x_train,y_train)

    #prediction
    predicted_dt = model_dt.predict(x_test)

    # from sklearn import metrics
    # print('Accuracy Score:', metrics.accuracy_score(y_test,y_pred))

    # from sklearn.metrics import confusion_matrix
    # cm = confusion_matrix(y_test, y_pred)

    # Create Decision Tree classifer object
    model_dt = DecisionTreeClassifier(criterion="entropy", max_depth=3)# Train Decision Tree Classifer
    model_dt.fit(x_train,y_train)#Predict the response for test dataset
    # print_score(model_dt, x_train, y_train, x_test, y_test, train=True)
    # print_score(model_dt, x_train, y_train, x_test, y_test, train=False)

def plotGraph_knn():
    # Visualising the Test set results
    # from matplotlib.colors import ListedColormap
    x_set, y_set = x_test, y_test
    x1, x2 = np.meshgrid(np.arange(start = x_set[:,0].min() - 1, stop = x_set[:,0].max() + 1, step = 0.01),
                        np.arange(start = x_set[:,1].min() - 1, stop = x_set[:,1].max() + 1, step = 0.01))
    # plt.contourf(x1, x2, model_knn.predict(np.array([x1.ravel(), x2.ravel()]).T).reshape(x1.shape),
    #             alpha = 0.75, cmap = ListedColormap(('red', 'green', "blue", "orange", "yellow")))
    plt.xlim(x1.min(), x1.max())
    plt.ylim(x2.min(), x2.max())
    for i, j in enumerate(np.unique(y_set)):
        plt.scatter(x_set[y_set == j, 0], x_set[y_set == j, 1],
                    c = ListedColormap(('red', 'green', "blue", "orange", "yellow", "purple", "pink"))(i), label = j)
    plt.title('KNN')
    plt.xlabel('1st PCA')
    plt.ylabel('2nd PCA')
    plt.legend()
    plt.show()

def plotGraph_dt():
    y_pred = model_dt.predict(x_test)# Model Accuracy, how often is the model_dt correct?
    print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
    fig = plt.figure(figsize=(25,20))
    tree.plot_tree(model_dt, filled = True, rounded = True, max_depth = 3)
    plt.show()
    X_set, y_set = x_test, y_test
    X1, X2 = np.meshgrid(np.arange(start = X_set[:,0].min()-1, stop= X_set[:,0].max()+1, step = 0.01),np.arange(start = X_set[:,1].min()-1, stop= X_set[:,1].max()+1, step = 0.01))
    # plt.contourf(X1,X2, model_dt.predict(np.array([X1.ravel(), X2.ravel()]).T).reshape(X1.shape), alpha=0.75, cmap = ListedColormap(("red","green")))
    plt.xlim(X1.min(), X1.max())
    plt.ylim(X2.min(), X2.max())
    for i,j in enumerate(np.unique(y_set)):
        plt.scatter(X_set[y_set==j,0],X_set[y_set==j,1], 
                    c = ListedColormap(('red', 'green', "blue", "orange", "yellow", "purple", "pink"))(i), label = j)
    plt.title("Decision Tree(Test set)")
    plt.xlabel("Age")
    plt.ylabel("Estimated Salary")
    plt.legend()
    plt.show()


if __name__ == "__main__":
    ## Remove deprecated warnings to show more useful information
    warnings.filterwarnings("ignore")
    matplotlib_axes_logger.setLevel('ERROR')
    
    if len(sys.argv) != 2:
        print("Error: Program requires one argument - root folder of log files.")
        print(f"Arguments count: {len(sys.argv)}")
        for i, arg in enumerate(sys.argv):
            print(f"Argument {i:>6}: {arg}")
    else:
        if os.path.exists(sys.argv[1]):
            print(sys.argv[1]) # Remove this line
            ## Reasons to not use OneHotEncoder/get_dummies ###
            df = readLogs(sys.argv[1])

            ### Splitting data into features and target ###
            tmpdf = df.copy()
            split = splitTarget(tmpdf)
            tmpdf = split[0]
            target = split[1]
            df = tmpdf.copy()

            #####################
            ### Label Encoder ###
            #####################
            tmptarget = target.copy()
            split = labelEncode(tmpdf, tmptarget)
            tmpdf = split[0]
            tmptarget = split[1]
            ##### MACHINE LEARNING CODES HERE #####
            X = list(zip(tmpdf['time_diff_ms'], tmpdf['request'], tmpdf['status'], tmpdf['size'], tmpdf['referer'], tmpdf['user_agent']))
            Y = list(tmptarget['technique'])


            # x_train, x_test, y_train, y_test = sklearn.model_selection.train_test_split(X, Y, test_size=0.1, random_state=42)

            # model_knn = KNeighborsClassifier(n_neighbors=69)
            # model_knn.fit(x_train, y_train)
            # accuracy = model_knn.score(x_test, y_test)

            # print_score(model_knn, x_train, y_train, x_test, y_test, train=True)

            # predicted = model_knn.predict(x_test)
            techniques = [0, 1, 2, 3, 4, 5, 6]
            print("K NEAREST NEIGHBORS")
            models_knn(X, Y)
            plotGraph_knn()
            knn_bar_lbl = print_score(model_knn, x_train, y_train, x_test, y_test, train=False)
            print("KNN BAR LABEL", knn_bar_lbl)

            print("DECISION TREE")
            models_dt(X, Y)
            plotGraph_dt()
            dt_bar_lbl = print_score(model_dt, x_train, y_train, x_test, y_test, train=False)

            # print(f"Accuracy: {accuracy}")

            ###############################
            ### CatBoost Target Encoder ###
            ###############################
            techniques = target['technique'].unique().tolist()
            tmpdf = df.copy()
            tmptarget = target.copy()
            result = catboostEncode(tmpdf, tmptarget)
            tmpdf = result[0]
            tmptarget = result[1]
            ##### MACHINE LEARNING CODES HERE #####
            X = list(zip(tmpdf['time_diff_ms'], tmpdf['request'], tmpdf['status'], tmpdf['size'], tmpdf['referer'], tmpdf['user_agent']))
            Y = list(tmptarget['technique'])

            # x_train, x_test, y_train, y_test = sklearn.model_selection.train_test_split(X, Y, test_size=0.1, random_state=42)

            # model_knn = KNeighborsClassifier(n_neighbors=69)
            # model_knn.fit(x_train, y_train)
            # accuracy = model_knn.score(x_test, y_test)

            # print_score(model_knn, x_train, y_train, x_test, y_test, train=True)
            # print(f"Accuracy: {accuracy}")
            print("K NEAREST NEIGHBORS")
            models_knn(X, Y)
            plotGraph_knn()
            print_score(model_knn, x_train, y_train, x_test, y_test, train=False)
            knn_bar_cbe = print_score(model_knn, x_train, y_train, x_test, y_test, train=False)

            print("DECISION TREE")
            models_dt(X, Y)
            plotGraph_dt()
            dt_bar_cbe = print_score(model_dt, x_train, y_train, x_test, y_test, train=False)

            #################
            ### Final Run ###
            #################
            ### CatBoost Target encoder with filtering ###

            techniques = target['technique'].unique().tolist()


            dict_result_knn = {}
            dict_result_dt = {}
            # dict_result_svm = {}

            array_data = []
            first_loop = True

            for i in range(len(techniques)):
                original_df = df.copy()
                original_target = target.copy()
                tmpdf = df.copy()
                tmptarget = target.copy()
                tmptarget = filterByTechnique(tmptarget, techniques[i])
                result = catboostEncode(tmpdf, tmptarget)
                tmpdf = result[0]
                tmptarget = result[1]
                ##### MACHINE LEARNING CODES HERE #####
                X = list(zip(tmpdf['time_diff_ms'], tmpdf['request'], tmpdf['status'], tmpdf['size'], tmpdf['referer'], tmpdf['user_agent']))
                Y = list(tmptarget['technique'])

                X_original = list(zip(original_df['time_diff_ms'], original_df['request'], original_df['status'], original_df['size'], original_df['referer'], original_df['user_agent']))
                Y_original = list(original_target['technique'])

                # x_train, x_test, y_train, y_test = sklearn.model_selection.train_test_split(X, Y, test_size=0.1, random_state=42)
                # x_original_train, x_original_test, y_original_train, y_original_test = sklearn.model_selection.train_test_split(X_original, Y_original, test_size=0.1, random_state=42)

                # model_knn = KNeighborsClassifier(n_neighbors=69)
                # model_knn.fit(x_train, y_train)

                

                techniques_catboost = tmptarget['technique'].unique().tolist()
                # predicted_knn = model_knn.predict(x_test)
                # print("K NEAREST NEIGHBORS")
                modelsFilter_knn(X, Y, X_original, Y_original)
                # plotGraph_knn()

                print("DECISION TREE")
                modelsFilter_dt(X, Y, X_original, Y_original)
                # plotGraph_dt()

                

                if first_loop:
                    for j in range(len(x_original_test)):
                        array_data.append(x_original_test[j])

                result_1_knn = result_1(techniques_catboost, predicted_knn, y_test)
                result_1_dt = result_1(techniques_catboost, predicted_dt, y_test)
                # result_1_svm = result_1(techniques_catboost, predicted_svm, y_test)


                dict_string_1 = ["_predicted", "_actual"]

                for j in range(len(dict_string_1)):
                    add_dict(dict_result_knn, str(techniques[i]) + dict_string_1[j], result_1_knn[j])
                    add_dict(dict_result_dt, str(techniques[i]) + dict_string_1[j], result_1_dt[j])
                    # add_dict(dict_result_svm, str(techniques[i]) + dict_string_1[j], result_1_svm[j])

                first_loop = False

            result_2_knn = result_2(dict_result_knn, techniques, array_data)
            result_2_dt = result_2(dict_result_dt, techniques, array_data)
            # result_2_svm = result_2(dict_result_svm, techniques, array_data)

            dict_strings_2 = [
                "overlap_count",
                "overlap_index_array",
                "overlap_x_test",
                "missing_count",
                "missing_index_array",
                "missing_x_test"
            ]

            for i in range(len(dict_strings_2)):
                add_dict(dict_result_knn, dict_strings_2[i], result_2_knn[i])
                add_dict(dict_result_dt, dict_strings_2[i], result_2_dt[i])
                # add_dict(dict_result_svm, dict_strings_2[i], result_2_svm[i])


            # print_score(model_knn, x_train, y_train, x_test, y_test, train=True)

            # for key in dict_result_knn:
            #     print(f"{key}: {dict_result_knn[key]}")

            df_list = [knn_bar_lbl, knn_bar_cbe, dt_bar_lbl, dt_bar_cbe]

            nrow = 2
            ncol = 2

            print("TESTSETSETSETSETSETSETSTSETSETSET")
            fig, axs = plt.subplots(nrow, ncol)
            # axs[0, 0].plot(knn_bar_lbl["accuracy"], knn_bar_lbl["classes"])
            # axs[0, 0].plot()
            # sns.barplot(data=knn_bar_lbl)
            # axs[0, 0].plot(knn_bar_lbl)
            # axs[0, 0].set_ylabel("KNN")
            # axs[0, 0].title("LABEL ENCODE")

            # axs[0, 1].plot(knn_bar_cbe)
            # axs[0, 1].title("CATBOOST ENCODE")
            count = 0
            for r in range(nrow):
                for c in range(ncol):
                    df_list[count].plot(ax=axs[r,c], kind='bar')
                    count+=1

            # axs[0,0].setylabel("KNN")
            # axs[0, 0].title("LABEL ENCODE")


            plt.tight_layout()
            fig = plt.gcf()
            fig.set_size_inches(27, 9)
            plt.suptitle('Dashboard', y=1.01, fontsize=32)
            plt.show()
        else:
            print("Error: Path does not exist.")
            exit(1)