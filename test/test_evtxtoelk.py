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

elastic_data = elastic_client.search(index="winlogbeat*", size=10000, body=query_body)


#del elastic_data["took"]
hits_list = elastic_data["hits"]["hits"]

# for hit in hits_list:
#     # Remove the event created time fields 
#     del hit["_id"]
#     del hit["_source"]["@timestamp"]
    
elastic_data = (sorted(elastic_data["hits"]["hits"],
       key = lambda x: x["_source"]["winlog"]["time_created"] ))



test_data = json.dumps(elastic_data, sort_keys=True, indent=4)

# Write the data to out.json for comparision
with open("expected_evtxtoelk.json", "w") as outfile:
    outfile.write(test_data)