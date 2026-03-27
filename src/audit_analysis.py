from pathlib import Path
import pandas as pd

#Define base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent

#Right path for the file
file_path = BASE_DIR / 'data' / 'access_log.csv'

#Load data
df = pd.read_csv(file_path)

#Convert timestamp
df['timestamp'] = pd.to_datetime(df['timestamp'])

#Create new columns
df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.day_name()

#Rule 1: Access outside business hours (8h - 18h)
df['outside_business_hours'] = df['hour'].apply(lambda x: x < 8 or x > 18)

#Rule 2: Weekend access
df['weekend_access'] = df['day_of_week'].isin(['Saturday', 'Sunday'])

#Rule 3: High privilege users
df['high_privilege'] = df['access_level'] == 'high'

#Combine flags
df['risk_flag'] = df[['outside_business_hours', 'weekend_access', 'high_privilege']].any(axis=1)

#Filter suspicious records
findings = df[df['risk_flag'] == True]

#Save output
findings.to_csv('../output/findings_report.csv', index=False)

#Print summary
print("=== AUDIT SUMMARY ===")
print(f"Total records: {len(df)}")
print(f"Suspicious records: {len(findings)}")

print("\nDetails:")
print(findings)