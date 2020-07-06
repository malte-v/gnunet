#!/bin/bash

# Deploy docs from buildbot

cd doc
make html
cd ..
chmod -R ag+rX doc/
rsync -a --delete doc/ handbook@firefly.gnunet.org:~/doc_deployment/
