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

elastic_data = elastic_client.search(index="filebeat*", size=10000, body=query_body)


del elastic_data["took"]
hits_list = elastic_data["hits"]["hits"]
print(len(hits_list))

for hit in hits_list:
    # Remove the event created time fields 
    del hit["_id"]
    del hit["_index"]
    del hit["_source"]["agent"]

    del hit["_source"]["log"]["offset"]
    del hit["_source"]["host"]
    if 'id' in hit["_source"]["event"]: del hit["_source"]["event"]["id"]
    if 'network' in hit["_source"] and 'protocol' in hit["_source"]["network"]: del hit["_source"]["network"]["protocol"]

    # Suricata fields
    del hit["_source"]["event"]["ingested"]

    # Zeek fields
    del hit["_source"]["event"]["created"]
    if 'original' in hit["_source"]["event"]: del hit["_source"]["event"]["original"]
    
    if 'zeek' in hit["_source"]:
        if 'session_id' in hit["_source"]["zeek"]: del hit["_source"]["zeek"]["session_id"]
        if 'files' in hit["_source"]["zeek"]: 
            if 'session_ids' in hit["_source"]["zeek"]["files"]: del hit["_source"]["zeek"]["files"]["session_ids"]
            if 'analyzers' in hit["_source"]["zeek"]["files"]: del hit["_source"]["zeek"]["files"]["analyzers"]

# Sort the events by @timestamp, and log file path    
elastic_data = sorted(elastic_data["hits"]["hits"],
       key = lambda x: (x["_source"]["@timestamp"], x["_source"]["log"]["file"]["path"]) )


test_data = json.dumps(elastic_data, sort_keys=True, indent=4)

with open("expected_zeek.json","r") as original_data_file:
    original_data = original_data_file.read()

if(original_data == test_data):
    print("Test passed!")
    exit(0)
else:
    print("Test Failed")
    exit(1)