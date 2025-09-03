#!/bin/bash

python3 trace_to_lkm.py -i $FORWARD_LINK -t $TESTBED_PACKAGE/$FORWARD_TRACE run
python3 trace_to_lkm.py -i $RETURN_LINK -t $TESTBED_PACKAGE/$RETURN_TRACE run
