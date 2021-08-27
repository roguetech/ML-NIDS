from flask import Flask, request
import pickle as p
import json
import pandas as pd
import logging
import os

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

def add_rule(target_packet):

    print("TP: ", target_packet)

    ip_src = target_packet[0]
    ip_dst = target_packet[1]
    port_src = target_packet[2]
    port_dst = target_packet[3]

    os.system("./sdn-module.py ip_src ip_dst port_src port_dst")

@app.route('/pred', methods=['POST'])

def pred():

    app.logger.info('Processing default request')
    data_json = request.get_json()

    #print(data_json)

    target_packet = [data_json["ip_src"], data_json["ip_dst"], data_json["port_src"], data_json["port_dst"]]

    del data_json["ip_src"]
    del data_json["ip_dst"]
    del data_json["port_src"]
    del data_json["port_dst"]

    print(target_packet)

    #print(type(data_json))
    #print(data_json)

    print("Loaded Json")
    data_pd = pd.json_normalize(data_json).values
    prediction = model.predict(data_pd)

    score = tf.keras.losses.mae(prediction, data_pd)

    #print(score)
    threshold = np.mean(score) + np.std(score)
    print("Threshold: ", threshold)

    if threshold > 0.05:
        data_value = "attack " + str(threshold)
        add_rule(target_packet)
    else:
        data_value = "normal " + str(threshold)

    #print(data_json)
    #print(data_value)

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