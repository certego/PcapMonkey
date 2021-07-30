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
    # del hit["_source"]["event"]["id"]

    # Suricata fields
    del hit["_source"]["event"]["ingested"]

    # Zeek fields
    del hit["_source"]["event"]["created"]
    # del hit["_source"]["zeek"]["session_id"]
    # del hit["_source"]["zeek"]["files"]["session_ids"]
    # del hit["_source"]["zeek"]["files"]["analyzers"]
    
elastic_data = sorted(elastic_data["hits"]["hits"],
       key = lambda x: (x["_source"]["@timestamp"]) )


test_data = json.dumps(elastic_data, sort_keys=True, indent=4)

# Write the data to out.json for comparision
with open("test_comb.json", "w") as outfile:
    outfile.write(test_data)