import pandas as pd
import numpy as np
import joblib, os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE

COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes',
    'dst_bytes','land','wrong_fragment','urgent','hot',
    'num_failed_logins','logged_in','num_compromised','root_shell',
    'su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate',
    'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate','label','difficulty'
]

ATTACK_MAP = {
    'normal':'normal',
    'back':'dos','land':'dos','neptune':'dos','pod':'dos',
    'smurf':'dos','teardrop':'dos','apache2':'dos',
    'udpstorm':'dos','processtable':'dos','mailbomb':'dos',
    'ipsweep':'probe','nmap':'probe','portsweep':'probe',
    'satan':'probe','mscan':'probe','saint':'probe',
    'ftp_write':'r2l','guess_passwd':'r2l','imap':'r2l',
    'multihop':'r2l','phf':'r2l','spy':'r2l',
    'warezclient':'r2l','warezmaster':'r2l','sendmail':'r2l',
    'named':'r2l','snmpgetattack':'r2l','snmpguess':'r2l',
    'xlock':'r2l','xsnoop':'r2l','httptunnel':'r2l',
    'buffer_overflow':'u2r','loadmodule':'u2r','perl':'u2r',
    'rootkit':'u2r','sqlattack':'u2r','xterm':'u2r','ps':'u2r'
}

def load_data():
    print("[1/5] Loading dataset...")
    df_train = pd.read_csv('data/KDDTrain+.txt',
                           header=None, names=COLUMNS)
    df_test  = pd.read_csv('data/KDDTest+.txt',
                           header=None, names=COLUMNS)
    df_train.drop('difficulty', axis=1, inplace=True)
    df_test.drop('difficulty',  axis=1, inplace=True)
    print(f"      Train: {len(df_train)} rows | Test: {len(df_test)} rows")
    return df_train, df_test

def preprocess(df_train, df_test):
    print("[2/5] Preprocessing and encoding...")
    df_train['label'] = df_train['label'].map(
        lambda x: ATTACK_MAP.get(x.strip(),'other'))
    df_test['label']  = df_test['label'].map(
        lambda x: ATTACK_MAP.get(x.strip(),'other'))
    le = LabelEncoder()
    for col in ['protocol_type','service','flag']:
        df_train[col] = le.fit_transform(df_train[col])
        df_test[col]  = le.transform(df_test[col])
    X_train = df_train.drop('label', axis=1).values
    y_train = df_train['label'].values
    X_test  = df_test.drop('label', axis=1).values
    y_test  = df_test['label'].values
    return X_train, y_train, X_test, y_test

def apply_smote(X_train, y_train):
    print("[3/5] Applying SMOTE to balance classes...")
    sm = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    print(f"      After SMOTE: {len(X_res)} training samples")
    return X_res, y_res

def train(X_train, y_train):
    print("[4/5] Training Random Forest (100 trees)...")
    print("      This takes 3-8 minutes — please wait...")
    model = RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("      Training complete!")
    return model

def evaluate_and_save(model, X_test, y_test):
    print("[5/5] Evaluating and saving model...")
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n{'='*45}")
    print(f"  Test Accuracy : {acc*100:.2f}%")
    print(f"{'='*45}")
    print(classification_report(y_test, y_pred))
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/rf_model.pkl')
    print("\n  Model saved to models/rf_model.pkl")
    print("  Training complete — never run this again!\n")

if __name__ == '__main__':
    df_train, df_test         = load_data()
    X_tr, y_tr, X_te, y_te   = preprocess(df_train, df_test)
    X_tr, y_tr                = apply_smote(X_tr, y_tr)
    model                     = train(X_tr, y_tr)
    evaluate_and_save(model, X_te, y_te)