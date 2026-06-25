import sys
import pandas as pd
import numpy as np
import sklearn
import xgboost as xgb
import flask
import flask_cors
import joblib
import matplotlib
import requests

print("Python version:", sys.version)
print("pandas:", pd.__version__)
print("numpy:", np.__version__)
print("scikit-learn:", sklearn.__version__)
print("xgboost:", xgb.__version__)
print("flask:", flask.__version__)
print("flask-cors: OK")
print("joblib:", joblib.__version__)
print("matplotlib:", matplotlib.__version__)
print("requests:", requests.__version__)
print("\nAll libraries loaded successfully. Environment is ready.")