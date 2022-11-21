import pandas as pd
import re
import ipaddress
import datetime

PORT_REGEX = \
    '^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$'

INTEGER_REGEX = r'^(?:0|(?:[1-9](?:\d{0,2}(?:,\d{3})+|\d*)))$'
MAC_ADDRESS_REGEX = ("^([0-9A-Fa-f]{2}[:-])" +
                     "{5}([0-9A-Fa-f]{2})|" + "([0-9a-fA-F]{4}\\." + "[0-9a-fA-F]{4}\\." + "[0-9a-fA-F]{4})$")

BAD_VALUE_LIST = ['-']


def sort_values(dataframe, column_header):  # sort data frame by a column
    dataframe.sort_values(by=column_header, ascending=True)
    return dataframe


def remove_null_columns(dataframe):
    dataframe = dataframe.loc[:, ~dataframe.columns.str.contains('^Unnamed')]
    return dataframe


def remove_df_entry(dataframe, column, list):
    for bad_value in list:
        dataframe.drop(dataframe[dataframe[column] == bad_value].index, inplace=True)
    return dataframe


def check_port_numbers(dataframe):  # detect data like ip addresses in ports whatever
    port_columns = ['destination.port', 'source.port']
    validate_values(dataframe, port_columns, PORT_REGEX)
    return dataframe


def check_ip_addresses(dataframe):
    ipaddr_columns = ['destination.ip', 'source.ip']
    wrong_list = []
    for column in ipaddr_columns:
        for value in dataframe[column].values:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                wrong_list.append(value)
        dataframe = remove_df_entry(dataframe, column, wrong_list)
    return dataframe


def check_mac_adresses(dataframe):
    macaddr_columns = ['destination.mac', 'source.mac', 'host.mac']
    validate_values(dataframe, macaddr_columns, MAC_ADDRESS_REGEX)
    return dataframe


def clean_bytes_values(dataframe):
    bytes_columns = ['destination.bytes', 'network.bytes', 'source.bytes', 'destination.packets', 'network.packets',
                     'source.packets']
    for column in bytes_columns:
        dataframe[column] = dataframe[column].replace('-', '0')
    validate_values(dataframe, bytes_columns, INTEGER_REGEX)
    return dataframe


def validate_values(dataframe, column_list, regex):
    for column in column_list:
        correct_list = list(filter(re.compile(regex).match, dataframe[column].values.tolist()))
        wrong_list = (list(set(dataframe[column].values.tolist()) - set(correct_list)))
        remove_df_entry(dataframe, column, wrong_list)


def replace_empty_bytes(dataframe, column):
    dataframe[column] = dataframe[column].replace('-', '0')


def universal_timestamp_converter(dataframe, column):
    new_timestamp_list = []
    for timestamp in dataframe[column].values:
        timestamp = timestamp.split(' @')
        timestamp[0] = str(datetime.datetime.strptime(timestamp[0], '%b %d %Y')).split(' ')[0]
        timestamp = ''.join(timestamp)
        # timestamp = '\'' + timestamp  # for excel
        new_timestamp_list.append(timestamp)
    dataframe[column] = new_timestamp_list
    # print(dataframe['event.start'].values)
    return dataframe


def sort_time_ascending(dataframe):  # dont look at timestamp but event.start instead
    dataframe = dataframe.sort_values(by=['event.start'], ascending=True)
    return dataframe


def get_columns_with_all_single_values(dataframe):  # remove columns with the same values as it does not help analysis
    same_value_columns = []
    for column in dataframe.columns:
        if (dataframe[column] == dataframe[column][0]).all():
            same_value_columns.append(column)
    return same_value_columns


def drop_redundant_columns(dataframe, columns):
    columns_to_remove = get_columns_with_all_single_values(dataframe)
    columns_to_remove = columns_to_remove + columns
    columns_to_remove = list(set(columns_to_remove))  # remove duplicates
    for column in columns_to_remove:
        dataframe.drop(column, axis=1, inplace=True)


def get_null_counts(dataframe):
    null_counts = dataframe.isnull().sum()
    print("Number of null values in each column:\n{}".format(null_counts))


def output_to_csv(dataframe):
    dataframe.to_csv(r'Webserver_logs/traffic_cleaned.csv')


def get_keyword_columns(dataframe):  # only drop keyword columns if it matches to the original column
    keyword_cols = [col for col in dataframe.columns if 'keyword' in col]
    cols_to_remove = []
    for column in keyword_cols:
        original_column = column.split('.k')[0]
        if dataframe[column].equals(dataframe[original_column]):
            cols_to_remove.append(column)
    for column in keyword_cols:
        dataframe.drop(column, axis=1, inplace=True)
    return cols_to_remove


def filter_only_webserver_traffic(dataframe): # Filter 192.168.91.1
    dataframe = dataframe.loc[(dataframe['destination.ip'] == '192.168.91.1') |
                              (dataframe['source.ip'] == '192.168.91.1')]
    return dataframe


def remove_duplicate_ids_columns(dataframe):
    dataframe.drop('_id', axis=1, inplace=True)


def main():
    df = pd.read_csv(r'Webserver_logs/traffic_raw.csv')
    df = df.replace(',', '', regex=True)
    print('Row count is:', len(df.index))
    print('Column count is:', df.shape[1])
    check_port_numbers(df)
    check_ip_addresses(df)
    check_mac_adresses(df)
    clean_bytes_values(df)
    df = remove_null_columns(df)
    universal_timestamp_converter(df, 'event.start')
    universal_timestamp_converter(df, 'event.end')
    universal_timestamp_converter(df, '@timestamp')
    df = sort_time_ascending(df)
    # print(df.columns[df.isna().any()].tolist())

    drop_redundant_columns(df, ['_score'])

    # df = universal_timestamp_converter(df)

    # Move actual time to first column for convenience
    first_column = df.pop('event.start')
    second_column = df.pop('event.end')
    df.insert(0, 'event.start', first_column)
    df.insert(1, 'event.end', second_column)
    # Ensure the index column is correct
    get_keyword_columns(df)
    df = filter_only_webserver_traffic(df)
    # get_null_counts(df)
    df.reset_index(drop=True, inplace=True)
    remove_duplicate_ids_columns(df)
    output_to_csv(df)
    print('Row count is:', len(df.index))
    print('Column count is:', df.shape[1])


if __name__ == "__main__":
    main()
