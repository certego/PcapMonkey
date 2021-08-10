#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import json

elastic_client = Elasticsearch(hosts=["localhost:9200"])

# Elasticsearch query data
query_body = {
    "query": {
    "match_all": {}
    }
}

elastic_data = (elastic_client.search(index="winlogbeat*", size=10000, body=query_body))

hits_list = elastic_data["hits"]["hits"]
for hit in hits_list:
    # Remove the timestamp field in each hit 
    del hit["_id"]
    if '@timestamp' in hit['_source']:
        del hit['_source']['@timestamp']

# Sort events by @timestamp
elastic_data = (sorted(elastic_data["hits"]["hits"],
       key = lambda x: x["_source"]["winlog"]["time_created"] if('winlog' in x["_source"]) else x['_index'] ))

test_data = json.dumps(elastic_data, sort_keys=True, indent=4)

with open("expected_evtxtoelk.json","r") as original_data_file:
    original_data = original_data_file.read()

if(original_data == test_data):
    print("Test passed!")
    exit(0)
else:
    print("Test Failed")
    exit(1)