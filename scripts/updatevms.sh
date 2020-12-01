#! /bin/bash

ssh 1481 -C "sudo zypper -n up -l --no-recommends"
ssh 1859 -C "sudo zypper -n up -l --no-recommends"
ssh 793 -C "sudo zypper -n up -l --no-recommends"
