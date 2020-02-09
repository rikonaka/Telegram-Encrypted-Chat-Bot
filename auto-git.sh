#!/bin/bash

git add .

echo -n "Enter your commit message: "
read message

git commit -m "$message"
git push origin master
