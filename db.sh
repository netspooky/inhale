#!/bin/bash

query=$1
curl localhost:9200/_search?q=$query

