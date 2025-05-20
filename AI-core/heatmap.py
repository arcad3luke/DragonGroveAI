import matplotlib.pyplot as plt  # ✅ This ensures plt is recognized
import numpy as np  # ✅ Required for array handling
def generate_heatmap(risk_data):
    risk_size = len(risk_data)
    
    if risk_size != 9:
        print(f"⚠️ Warning: Expected 9 risk levels, received {risk_size}. Auto-adjusting.")
        risk_data = risk_data[:9] + [0] * (9 - risk_size)  # Fill missing slots

    risk_matrix = np.array(risk_data).reshape((3, 3))
    plt.imshow(risk_matrix, cmap='hot', interpolation='nearest')
    plt.colorbar(label="Risk Level")
    plt.title("DragonGroveAI Threat Heatmap")
    plt.show()
