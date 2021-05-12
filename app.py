from flask import Flask, request
import pickle as p
import json
import pandas as pd
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

@app.route('/pred', methods=['POST'])

def pred():

    app.logger.info('Processing default request')
    data_json = request.get_json()

    print("Loaded Json")
    data_pd = pd.json_normalize(data_json)
    prediction = model.predict(data_pd)

    return str(prediction)

if __name__ == '__main__':
    '''
    model_location = '/home/patrick/coding/ML-NIDS/network_intrusion.pickle'
    model = p.load(open(model_location, 'rb'))
    '''
    from keras.models import load_model
    model = load_model('/home/patrick/coding/autoencoder_model.h5')
    app.run()