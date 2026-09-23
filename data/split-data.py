import gc
import os
import time
import pandas as pd
from sklearn.model_selection import train_test_split


BASE = (
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if '__file__' in globals()
    else os.path.abspath('.')
)

INPUT = os.path.join(BASE, 'dataset', 'QUT-DV25.csv')

if not os.path.exists(INPUT):
    raise FileNotFoundError(f"[!] Input file not found: {INPUT}")

TRAIN = os.path.join(BASE, 'dataset', 'train.csv')
VAL = os.path.join(BASE, 'dataset', 'val.csv')
TEST = os.path.join(BASE, 'dataset', 'test.csv')

RANDOM = 3033


def split_data():

    t = time.time()

    print(f"[*] Reading: {os.path.basename(INPUT)}")
    df = pd.read_csv(INPUT)
    print(f"[+] Loaded: {len(df):,} samples | {df.shape[1]} columns")

    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        random_state=RANDOM,
        stratify=df['Level']
    )

    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=RANDOM,
        stratify=temp_df['Level']
    )

    del df, temp_df
    gc.collect()

    os.makedirs(os.path.dirname(TRAIN), exist_ok=True)
    train_df.to_csv(TRAIN, index=False)
    val_df.to_csv(VAL, index=False)
    test_df.to_csv(TEST, index=False)

    print(f"[+] Train: {TRAIN} ({len(train_df):,} samples)")
    print(f"[+] Val  : {VAL} ({len(val_df):,} samples)")
    print(f"[+] Test : {TEST} ({len(test_df):,} samples)")
    print(f"[+] Completed in {time.time() - t:.2f}s")

    for name, part in [('Train', train_df), ('Val', val_df), ('Test', test_df)]:
        b = (part['Level'] == 0).sum()
        m = (part['Level'] == 1).sum()
        total = len(part)
        print(f"- {name:<5}: {total:>5,} samples | Benign: {b:>5,} ({b/total*100:.2f}%) | Malicious: {m:>5,} ({m/total*100:.2f}%)")

    del train_df, val_df, test_df
    gc.collect()


if __name__ == '__main__':
    split_data()