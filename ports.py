import pandas as pd
import os
import requests

if os.path.exists('ports.csv'):
    pass
else:
    url = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
    r = requests.get(url)
    open('ports.csv', 'wb').write(r.content)

ports = pd.read_csv('ports.csv')
#print(ports.head())

service = ports.loc[ports['Port Number'] == '53', 'Service Name']
print(service)