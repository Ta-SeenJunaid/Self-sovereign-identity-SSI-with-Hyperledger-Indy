#!/bin/bash

docker build -f indy-pool.dockerfile -t indy_dev_pool .
echo "Successful process of indy_pool image building"
docker build -f indy-dev.dockerfile -t indy_dev .
echo "Successful process of indy_dev image building"
