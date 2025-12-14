# 1. into mr test dict
cd llm-aflmet/tests/mr

# 2. execute mr test
./run.sh mqtt mr_test_seeds/mqtt_mr_test_seeds

### arguments:
- arg 1: proto. e.g. mqtt/ftp/sip...
- arg 2: test seeds dir.

# 3. the output is in out dir.