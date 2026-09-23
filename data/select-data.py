import gc
import glob
import os
import time

import pandas as pd


BASE = (
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if '__file__' in globals()
    else os.path.abspath('.')
)

DATASET = os.path.join(BASE, 'dataset', 'QUT-DV25-Processed')
OUTPUT = os.path.join(BASE, 'dataset', 'QUT-DV25.csv')

if not os.path.exists(DATASET):
    raise FileNotFoundError(f"[!] Dataset directory not found: {DATASET}")

FEATURES = [
    # Opensnoop
    'Root_DIR_Installation',
    'Temporary_DIR_Installation',
    'Home_DIR_Installation',
    'User_Access',
    'Sys_Access',
    'Etc_DIR_Installation',
    'Other_DIR_Installation',

    # TCP
    'State_Transition',
    'Local_IP_Address_Access',
    'Remote_IP_Address_Access',
    'Local_Port_Access',
    'Remote_Port_Access',

    # Filetop
    'Read_Processes',
    'Write_Processes',
    'Read_Data_Transfer_Processes',
    'Write_Data_Transfer_Processes',
    'File_Access_Processes',

    # Install
    'Total_Dependencies',
    'Direct_Dependencies',
    'Indirect_Dependencies',

    # SysCall
    'File_Operations',
    'Network_Operations',
    'Process_Management_Operations',
    'IO_Operations',
    'Time_Operations',
    'Security_Operations',

    # Pattern
    'Pattern_1',
    'Pattern_2',
    'Pattern_3',
    'Pattern_4',
    'Pattern_5',
    'Pattern_6',
    'Pattern_7',
    'Pattern_8',
    'Pattern_9',
    'Pattern_10'
]


def load_traces():
    t = time.time()

    csv_files = glob.glob(
        os.path.join(DATASET, '**', '*.csv'),
        recursive=True
    )

    csv_files = [
        f for f in sorted(csv_files)
        if os.path.abspath(f) != os.path.abspath(OUTPUT)
    ]

    if not csv_files:
        raise FileNotFoundError(f"[!] No CSV files found in: {DATASET}")

    merged_df = None

    for path in csv_files:
        print(f"[*] Reading: {os.path.relpath(path, DATASET)}")
        df = pd.read_csv(path)
        df.columns = [c.strip() for c in df.columns]

        if 'Package_Name' not in df.columns:
            continue

        if merged_df is None:
            merged_df = df
        else:
            new_cols = [c for c in df.columns if c not in merged_df.columns]
            if new_cols:
                df_to_merge = df[['Package_Name'] + new_cols]
                merged_df = pd.merge(
                    merged_df,
                    df_to_merge,
                    on='Package_Name',
                    how='inner'
                )
                del df_to_merge
        del df
        gc.collect()

    print(f"\n[+] Merged: {len(merged_df):,} packages | {merged_df.shape[1]} columns")
    print(f"[+] Completed in {time.time() - t:.2f}s")

    return merged_df


def extract_features(df):
    t = time.time()
    cols = ['Package_Name'] + FEATURES + ['Level']

    missing_cols = [
        col
        for col in cols
        if col not in df.columns
    ]

    if missing_cols:
        raise KeyError(f"[!] Missing required columns in dataset: {missing_cols}")

    selected_df = df[cols].copy()
    print(f"\n[+] Extracted: {selected_df.shape[0]:,} samples | {selected_df.shape[1]} columns")
    print(f"[+] Completed in {time.time() - t:.2f}s")

    return selected_df


def main():
    raw_df = load_traces()
    selected_df = extract_features(raw_df)

    del raw_df
    gc.collect()

    t = time.time()
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    selected_df.to_csv(OUTPUT, index=False)

    print(f"\n[+] Saved: {OUTPUT}")
    print(f"[+] Completed in {time.time() - t:.2f}s")

    for val, count in selected_df['Level'].value_counts().items():
        name = "Benign" if val == 0 else "Malicious"
        print(f"Level {name:<9}: {count:>6,} - {count/len(selected_df)*100:.2f}%")

    print(f"\n[*] {len(selected_df.columns)} features:")
    for idx, col in enumerate(selected_df.columns, 1):
        print(f"{idx:2d}. {col}")

    del selected_df
    gc.collect()


if __name__ == '__main__':
    main()