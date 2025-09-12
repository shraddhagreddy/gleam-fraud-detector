import random
import csv

# Config
num_samples = 500  # how many rows to generate
output_file = "fraud_training_data.csv"

# Possible ASN values (fake ISP numbers)
asn_values = [12345, 23456, 34567, 45678, 56789]

with open(output_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    # Header
    writer.writerow(["actions_per_minute", "domain_type", "ip_asn", "duplicate_email", "fraud"])

    for _ in range(num_samples):
        actions_per_minute = random.randint(1, 50)   # user actions per minute
        domain_type = random.choice([0, 1])          # 0 = normal, 1 = disposable
        ip_asn = random.choice(asn_values)
        duplicate_email = random.choice([0, 1])      # whether email already seen

        # Simple fraud logic for labeling (to simulate real patterns)
        fraud = 0
        if actions_per_minute > 25:
            fraud = 1
        if domain_type == 1:
            fraud = 1
        if duplicate_email == 1 and actions_per_minute > 15:
            fraud = 1
        if random.random() < 0.1:  # add some noise
            fraud = 1 - fraud

        writer.writerow([actions_per_minute, domain_type, ip_asn, duplicate_email, fraud])

print(f"✅ Synthetic dataset saved to {output_file}")
