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

    #print(type(data_json))
    #print(data_json)

    print("Loaded Json")
    data_pd = pd.json_normalize(data_json).values
    prediction = model.predict(data_pd)
    #print("data pd: **** ", data_pd)
    #print("Prediction: **** ", prediction)

    score = tf.keras.losses.mae(prediction, data_pd)

    #print(score)
    threshold = np.mean(score) + np.std(score)
    print("Threshold: ", threshold)

    if threshold > 0.04:
        data_value = "attack " + str(threshold)
    else:
        data_value = "normal " + str(threshold)

    #print(data_json)
    print(data_value)

    return data_value

if __name__ == '__main__':
    '''
    model_location = '/home/patrick/coding/ML-NIDS/network_intrusion.pickle'
    model = p.load(open(model_location, 'rb'))
    '''
    from keras.models import load_model
    import numpy as np
    import tensorflow as tf
    model = load_model('/home/patrick/coding/ML-NIDS/autoencoder_2208.h5')
    app.run()