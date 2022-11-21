import pandas as pd
import numpy as np

PATH = 'Webserver_logs/fw_logs.txt'


def get_headers(file):
    f = open(file, "r")
    for line in f:
        if line.startswith("#Fields:"):
            line = line.strip()
            headers = line.split(' ')
    headers.pop(0)
    return headers


def get_columns_with_all_single_values(dataframe):  # remove columns with the same values as it does not help analysis
    same_value_columns = []
    for column in dataframe.columns:
        if (dataframe[column] == dataframe[column][0]).all():
            same_value_columns.append(column)
    return same_value_columns


def output_to_csv(dataframe):
    dataframe.to_csv(r'Webserver_logs/firewall_logs_cleaned.csv')


def format_data(file):
    headers = get_headers(file)
    df = pd.read_csv(
        PATH,
        sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',
        engine='python',
        na_values='-',
        header=None,
        usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        names=headers,
    )
    df = df.iloc[4:]
    return df


def drop_redundant_cols(dataframe):
    if get_columns_with_all_single_values(dataframe):
        for column in get_columns_with_all_single_values(dataframe):
            dataframe.drop(column, axis=1, inplace=True)
    dataframe.dropna(axis=1, how='all', thresh=None, subset=None, inplace=True)


def replace_blank_values(dataframe):
    dataframe.replace(r'^\s*$', np.nan, regex=True, inplace=True)


def main():
    df = format_data(PATH)
    df.reset_index(drop=True, inplace=True)
    drop_redundant_cols(df)
    replace_blank_values(df)
    print(df)
    output_to_csv(df)


if __name__ == "__main__":
    main()
