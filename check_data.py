import pandas as pd

TEST_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"

print(f"--- Checking file: {TEST_FILE} ---")

try:
    df = pd.read_csv(TEST_FILE, encoding='latin1')
    df.columns = [col.strip() for col in df.columns]

    if 'Label' in df.columns:
        print("Found the 'Label' column. Here are the counts of each traffic type:")
        print(df['Label'].value_counts())
    else:
        print("ERROR: Could not find the 'Label' column!")

except Exception as e:
    print(f"Error: {e}")