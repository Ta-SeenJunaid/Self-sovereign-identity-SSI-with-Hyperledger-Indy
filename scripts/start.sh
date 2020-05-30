#!/bin/bash


if [ "$#" -eq 0 ];
    then
        if [[ "$(docker ps -a -f status=running | grep indy_pool)" ]];
            then
                echo "entering " $(pwd) "directory"
                docker run -u root -it --net=host -p 127.0.0.1:8080:8080 -v $(pwd):/home/indy indy_dev
            else
                echo "entering " $(pwd) "directory"
                docker run -u root -itd --net=host -p 127.0.0.1:9701-9708:9701-9708 indy_dev_pool
                docker run -it -u root --net=host -p 127.0.0.1:8080:8080 -v $(pwd):/home/indy indy_dev
        fi;
    else
        if [[ "$(docker ps -a -f status=running | grep indy_pool)" ]];
            then
                echo "entering $1 directory"
                docker run -u root -itd --net=host -p 127.0.0.1:9701-9708:9701-9708 indy_dev_pool
                docker run -u root -it --net=host -p 127.0.0.1:8080:8080 -v "$1":/home/indy indy_dev
            else
                echo "entering $1 directory"
                docker run -u root -itd --net=host -p 127.0.0.1:9701-9708:9701-9708 indy_dev_pool
                docker run -u root -it --net=host -p 127.0.0.1:8080:8080 -v "$1":/home/indy indy_dev
        fi;
fi;

docker stop $(docker ps -a | grep '\indy_pool\|indy_dev' | awk '{print $1}')