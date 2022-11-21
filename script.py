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
  y = list(target['technique'])
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

        bar = df.iloc[:3, :7].T
        plt.show()
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

        bar = df.iloc[:3, :7].T
        plt.show()
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
    sc = StandardScaler()
    x_train = sc.fit_transform(x_train)
    x_test = sc.transform(x_test)

    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)
    
    model_knn = KNeighborsClassifier(n_neighbors=69)
    model_knn.fit(x_train, y_train)
    predicted_knn = model_knn.predict(x_test)

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
    predicted_knn = model_knn.predict(x_test)

def models_dt(x, y):    
    global model_dt, x_test, y_test, predicted_dt
    x_train, x_test, y_train, y_test =  train_test_split(x, y, test_size = 0.1, random_state = 42)

    sc_X = StandardScaler()
    x_train = sc_X.fit_transform(x_train)
    x_test = sc_X.transform(x_test)

    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)

    model_dt = DecisionTreeClassifier()
    model_dt.fit(x_train,y_train)

    #prediction
    predicted_dt = model_dt.predict(x_test)


    # Create Decision Tree classifer object
    # Train Decision Tree Classifer
    model_dt = DecisionTreeClassifier(criterion="entropy", max_depth=3)
    #Predict the response for test dataset
    model_dt.fit(x_train,y_train)

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

    model_dt = DecisionTreeClassifier()
    model_dt.fit(x_train,y_train)

    #prediction
    predicted_dt = model_dt.predict(x_test)


    # Create Decision Tree classifer object
    # Train Decision Tree Classifer
    model_dt = DecisionTreeClassifier(criterion="entropy", max_depth=3)
    #Predict the response for test dataset
    model_dt.fit(x_train,y_train)

def models_svm(x, y):
    global model_svm, x_train, x_test, y_train, y_test, predicted_svm
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 42)

    # Feature Scaling
    sc = StandardScaler()
    x_train = sc.fit_transform(x_train)
    x_test = sc.transform(x_test)


    # PCA TEST ##
    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)

    model_svm = SVC(kernel = 'rbf')
    model_svm.fit(x_train, y_train)
    predicted_svm = model_svm.predict(x_test)
    print_score(model_svm, x_train, y_train, x_test, y_test, train=True)

def modelsFilter_svm(x, y, X_original,Y_original):
    global x_test, y_test, predicted_svm, x_original_train, x_original_test, y_original_train, y_original_test
    x_train, x_test, y_train, y_test =  train_test_split(x, y, test_size = 0.1, random_state = 42)
    x_original_train, x_original_test, y_original_train, y_original_test = sklearn.model_selection.train_test_split(X_original, Y_original, test_size=0.1, random_state=42)

    # Feature Scaling
    sc = StandardScaler()
    x_train = sc.fit_transform(x_train)
    x_test = sc.transform(x_test)

    ## PCA TEST ##
    pca = PCA(n_components = 2)
    x_train = pca.fit_transform(x_train)
    x_test = pca.transform(x_test)

    model_svm = SVC(kernel = 'rbf')
    model_svm.fit(x_test, y_test)
    predicted_svm = model_svm.predict(x_test)

    print_score(model_svm, x_train, y_train, x_test, y_test, train=False)  
    x0, x1 = x_test, y_test

    xx, yy = np.meshgrid(np.arange(start = x0[:, 0].min() - 1, stop = x0[:, 0].max() + 1, step = 0.01),
                        np.arange(start = x0[:, 1].min() - 1, stop = x0[:, 1].max() + 1, step = 0.01))

    fig, ax = plt.subplots(figsize=(8,6))
    fig.patch.set_facecolor('white')

    labl1 = {0: "Every other technique", 1: "Filtered technique"}
    marker1 = {0: '*', 1: 'd'}

    colors = np.array(['green', 'pink'])
    for i, j in enumerate(np.unique(x1)):
        ax.scatter(x0[x1 == j, 0], x0[x1 == j, 1], c = colors[i], label = labl1[i],
                    s=70, marker=marker1[i], alpha=1)

    ax.scatter(model_svm.support_vectors_[:, 0], model_svm.support_vectors_[:, 1], s=40, facecolors='none',
              edgecolors='navy', label="Support Vectors")

    plt.contourf(xx, yy, model_svm.predict(np.array([xx.ravel(), yy.ravel()]).T).reshape(xx.shape),
                  alpha = 0.4, cmap = ListedColormap(('blue', 'red')))
    plt.xlim(xx.min(), xx.max())
    plt.ylim(yy.min(), yy.max())

    plt.legend()
    plt.title("SVM: CatBoost with Filter")
    plt.xlabel("1st PCA")
    plt.ylabel("2nd PCA")
    plt.show()

def plotGraph_knn():
    # Visualising the Test set results
    # from matplotlib.colors import ListedColormap
    x_set, y_set = x_test, y_test
    x1, x2 = np.meshgrid(np.arange(start = x_set[:,0].min() - 1, stop = x_set[:,0].max() + 1, step = 0.01),
                        np.arange(start = x_set[:,1].min() - 1, stop = x_set[:,1].max() + 1, step = 0.01))
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
    y_pred = model_dt.predict(x_test)
    print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
    fig = plt.figure(figsize=(25,20))
    tree.plot_tree(model_dt, filled = True, rounded = True, max_depth = 3)
    plt.show()
    X_set, y_set = x_test, y_test
    X1, X2 = np.meshgrid(np.arange(start = X_set[:,0].min()-1, stop= X_set[:,0].max()+1, step = 0.01),np.arange(start = X_set[:,1].min()-1, stop= X_set[:,1].max()+1, step = 0.01))
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

def plotGraph_svm():
    x0, x1 = x_test, y_test
    xx, yy = np.meshgrid(np.arange(start = x0[:, 0].min() - 1, stop = x0[:, 0].max() + 1, step = 0.01),
                        np.arange(start = x0[:, 1].min() - 1, stop = x0[:, 1].max() + 1, step = 0.01))

    fig, ax = plt.subplots(figsize=(8,6))
    fig.patch.set_facecolor('white')

    labl1 = {0: "t1021", 1: "t1053", 2: "t1059", 3: "t1190", 4: "t1204", 5:"t1592", 6: "t1595"}
    marker1 = {0: '*', 1: 'd', 2: 'o', 3: '^', 4: 'P', 5: 'x', 6:'+'}

    colors = np.array(['green', 'pink', 'yellow', 'black', 'orange', 'purple', 'blue'])

    for i, j in enumerate(np.unique(x1)):
        ax.scatter(x0[x1 == j, 0], x0[x1 == j, 1], c = colors[i], label = labl1[i],
                    s=70, marker=marker1[i], alpha=1)
    plt.contourf(xx, yy, models_svm.predict(np.array([xx.ravel(), yy.ravel()]).T).reshape(xx.shape),
                alpha = 0.4, cmap = "tab10")
    plt.xlim(xx.min(), xx.max())
    plt.ylim(yy.min(), yy.max())

    plt.legend()
    plt.title("SVM: CatBoost")
    plt.xlabel("1st PCA")
    plt.ylabel("2nd PCA")

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

            techniques = [0, 1, 2, 3, 4, 5, 6]
            print("K NEAREST NEIGHBORS")
            models_knn(X, Y)
            graph_knn_lbl = plotGraph_knn()
            knn_bar_lbl = print_score(model_knn, x_train, y_train, x_test, y_test, train=False)
            # print("KNN BAR LABEL", knn_bar_lbl)

            print("DECISION TREE")
            models_dt(X, Y)
            graph_dt_lbl = plotGraph_dt()
            dt_bar_lbl = print_score(model_dt, x_train, y_train, x_test, y_test, train=False)

            print("SVM")
            models_knn(X, Y)
            graph_svm_lbl = plotGraph_svm()
            svm_bar_lbl = print_score(model_svm, x_train, y_train, x_test, y_test, train=False)

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

            # print(f"Accuracy: {accuracy}")
            print("K NEAREST NEIGHBORS")
            models_knn(X, Y)
            graph_knn_cbe = plotGraph_knn()
            # print_score(model_knn, x_train, y_train, x_test, y_test, train=False)
            knn_bar_cbe = print_score(model_knn, x_train, y_train, x_test, y_test, train=False)

            print("DECISION TREE")
            models_dt(X, Y)
            graph_dt_cbe = plotGraph_dt()
            dt_bar_cbe = print_score(model_dt, x_train, y_train, x_test, y_test, train=False)

            print("SVM")
            models_svm(X, Y)
            graph_svm_cbe = plotGraph_svm()
            svm_bar_cbe = print_score(model_svm, x_train, y_train, x_test, y_test, train=False)

            #################
            ### Final Run ###
            #################
            ### CatBoost Target encoder with filtering ###
            techniques = target['technique'].unique().tolist()

            dict_result_knn = {}
            dict_result_dt = {}
            dict_result_svm = {}

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

                techniques_catboost = tmptarget['technique'].unique().tolist()

                print("K NEAREST NEIGHBORS")
                modelsFilter_knn(X, Y, X_original, Y_original)
                plotGraph_knn()

                print("DECISION TREE")
                modelsFilter_dt(X, Y, X_original, Y_original)
                plotGraph_dt()

                print("SVM")
                modelsFilter_svm(X, Y, X_original, Y_original)
                plotGraph_svm()

                

                if first_loop:
                    for j in range(len(x_original_test)):
                        array_data.append(x_original_test[j])

                result_1_knn = result_1(techniques_catboost, predicted_knn, y_test)
                result_1_dt = result_1(techniques_catboost, predicted_dt, y_test)
                result_1_svm = result_1(techniques_catboost, predicted_svm, y_test)


                dict_string_1 = ["_predicted", "_actual"]

                for j in range(len(dict_string_1)):
                    add_dict(dict_result_knn, str(techniques[i]) + dict_string_1[j], result_1_knn[j])
                    add_dict(dict_result_dt, str(techniques[i]) + dict_string_1[j], result_1_dt[j])
                    add_dict(dict_result_svm, str(techniques[i]) + dict_string_1[j], result_1_svm[j])

                first_loop = False

            result_2_knn = result_2(dict_result_knn, techniques, array_data)
            result_2_dt = result_2(dict_result_dt, techniques, array_data)
            result_2_svm = result_2(dict_result_svm, techniques, array_data)

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
                add_dict(dict_result_svm, dict_strings_2[i], result_2_svm[i])


            # for key in dict_result_knn:
            #     print(f"{key}: {dict_result_knn[key]}")

            df_list = [knn_bar_lbl, knn_bar_cbe, dt_bar_lbl, dt_bar_cbe, svm_bar_lbl, svm_bar_cbe]
            title_list = ["Label Encode\n     knn", "CatBoost Encode\n     knn", 
                            "Label Encode\n   Decision Tree", "CatBoost Encode\n   Decision Tree",
                            "Label Encode\n   SVM", "CatBoost Encode\n   SVM"]

            nrow = 3
            ncol = 2
            fig, axs = plt.subplots(nrow, ncol)
            count = 0
            for r in range(nrow):
                for c in range(ncol):
                    df_list[count].plot(ax=axs[r,c], kind='bar', title=title_list[count])
                    count+=1


            plt.tight_layout()
            fig = plt.gcf()
            fig.set_size_inches(27, 30)
            plt.suptitle('Dashboard', y=1.01, fontsize=32)
            plt.show()

        else:
            print("Error: Path does not exist.")
            exit(1)