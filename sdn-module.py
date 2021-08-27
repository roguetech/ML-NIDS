import json
import sys
import requests as re
import icecream as ic
import pandas as pd

controller_url =  'http://192.168.122.245:8181/restconf'
node_list = []
flow_tables = []

def main(src_ip, dst_ip, src_port, dst_port):
    print("SDN Module")
    print("Test: ", src_ip, dst_ip, src_port, dst_port)
    #get_all_nodes()
    #node = str(node_list[0])
    #get_all_flows()
    #flow = add_flow(0, "test1", node, "1.1.1.1", "2.2.2.2", "80", "11111")
    #print("Flow Response: ", flow)

def get_all_nodes():
    node_url = controller_url + '/operational/opendaylight-inventory:nodes'
    print(node_url)
    resp = re.get(node_url, auth=('admin', 'admin'))
    print(f"Status code: {resp.status_code}")
    resp_dict = resp.json()
    nodes_dict = resp_dict['nodes']#['node']
    #print(list(nodes_dict.id()))
    #print(nodes_dict)
    for i in nodes_dict['node']:
        node_list.append(i['id'])

def get_all_flows():
    for i in node_list:
        node_flows = controller_url + '/operational/opendaylight-inventory:nodes/node/' + i
        print(node_flows)
        resp = re.get(node_flows, auth=('admin', 'admin'))
        resp_dict = resp.json()
        print('Get All Flows')
   
        for i in resp_dict['node']:
            for j in i['flow-node-inventory:table']:
                if j['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] >= 1:
                    flow_tables.append(j)
        print(pd.DataFrame(flow_tables))

def add_flow(table, flow_id, node, src_ip, dst_ip, src_port, dst_port):
    print(node)

    src_ip = src_ip + "/32"
    dst_ip = dst_ip + "/32"

    print(type(dst_ip))
    print(dst_ip)

    node_flows = controller_url + '/operations/sal-flow:add-flow'
    node = "/opendaylight-inventory:nodes/opendaylight-inventory:node[opendaylight-inventory:id='" + node + "']"

    rule = {
     "input": {
         "node": node,
         "table_id": 0,
         "priority": 2,
         "match": {
            "ipv4-destination": dst_ip,
            "ipv4-source": src_ip,
            "ethernet-match": {
                 "ethernet-type": {
                     "type": 2048
                 }
            },
            "ip-match": {
                     "ip-dscp": 60,
                     "ip-protocol": 6,
                     "ip-ecn": 3
                 },
            "tcp-source-port": src_port,
            "tcp-destination-port": dst_port
         },
         "instructions": {
             "instruction": [
                 {
                     "order": 0,
                     "apply-actions": {
                         "action": [
                             {
                                 "order": 0,
                                 "drop-action": {}
                             }
                         ]
                     }
                 }
             ]
         }
     }
 }

    resp = re.post(node_flows, auth=('admin', 'admin'), data = json.dumps(rule), headers={'Content-type': 'application/yang.operation+json'})

    return resp

#def delete_flow();

if __name__ == "__main__":
    src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    src_port = sys.argv[3]
    dst_port = sys.argv[4]
    main(src_ip, dst_ip, src_port, dst_port)