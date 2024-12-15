import joblib
from sklearn.ensemble import RandomForestClassifier

# Load the previously saved model and predictor names
model = joblib.load('best_model.pkl')
predictor_names = joblib.load('predictor_names.pkl')

# Save the model again using the current version of scikit-learn
joblib.dump(model, 'best_model_resaved.pkl')
joblib.dump(predictor_names, 'predictor_names_resaved.pkl')
