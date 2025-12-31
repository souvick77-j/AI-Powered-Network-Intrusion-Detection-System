import scapy.all as scapy
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
def generate_sample_data(num_samples=1000):
    features = []
    labels = []
    for _ in range(num_samples):
        src_ip = np.random.randint(0, 255)  
        dst_ip = np.random.randint(0, 255)
        packet_len = np.random.randint(64, 1500)
        protocol = np.random.choice([6, 17]) 
        is_attack = np.random.choice([0, 1], p=[0.8, 0.2]) 
        features.append([src_ip, dst_ip, packet_len, protocol])
        labels.append(is_attack)
    return pd.DataFrame(features, columns=['src_ip', 'dst_ip', 'packet_len', 'protocol']), labels

df, labels = generate_sample_data()
X_train, X_test, y_train, y_test = train_test_split(df, labels, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

joblib.dump(model, 'nids_model.pkl')

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = int(packet[scapy.IP].src.split('.')[-1])  
        dst_ip = int(packet[scapy.IP].dst.split('.')[-1])
        packet_len = len(packet)
        protocol = packet[scapy.IP].proto
        features = [[src_ip, dst_ip, packet_len, protocol]]
        prediction = model.predict(features)[0]
        if prediction == 1:
            print(f"Intrusion detected: {packet.summary()}")

model = joblib.load('nids_model.pkl')
scapy.sniff(iface='eth0', prn=packet_callback, store=0)  