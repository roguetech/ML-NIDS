from flask import Flask, request
import pickle as p
import sklearn
import json
import numpy as np
import pandas as pd
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

@app.route('/pred')
@app.route('/')

def pred():

    #data1 = pd.DataFrame.from_dict(data, orient="index")
    #file = open('/home/patrick/Downloads/dump.txt', 'rb')
    app.logger.info('Processing default request')
    data_json = request.get_json()

    print("Loaded Json")
    #data_dict = p.load(file)
    data_dict = pd.read_json(data_json)
    #print(data_dict.transpose())
    print(data_dict)
    prediction = model.predict(data_dict)

    return prediction

if __name__ == '__main__':
    model_location = '/home/patrick/coding/ML-NIDS/network_intrusion.pickle'
    model = p.load(open(model_location, 'rb'))
    #test = pred()
    #print(test)
    app.run()